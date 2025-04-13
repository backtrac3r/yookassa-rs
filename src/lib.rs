use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client as ReqwestClient, Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

// --- Константы ---
const YOOKASSA_API_BASE_URL: &str = "https://api.yookassa.ru/v3/";
const IDEMPOTENCE_KEY_HEADER: &str = "Idempotence-Key";

#[derive(Error, Debug)]
pub enum YooKassaError {
    #[error("Ошибка сети или HTTP запроса: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Ошибка сериализации/десериализации JSON: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Ошибка API YooKassa (Статус: {status}): {message}")]
    ApiError {
        status: StatusCode,
        message: String,
        error_details: Option<YooKassaApiError>, // Детали ошибки от API
    },

    #[error("Неверный URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Неверное значение заголовка: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Отсутствует обязательное поле в ответе: {0}")]
    MissingField(String),
}

// Структура для парсинга тела ошибки от API YooKassa (если оно есть)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct YooKassaApiError {
    #[serde(rename = "type")]
    pub error_type: String, // Например, "error"
    pub id: String,          // Уникальный идентификатор ошибки
    pub code: String,        // Код ошибки (например, "invalid_request")
    pub description: String, // Описание ошибки для разработчика
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>, // Параметр, вызвавший ошибку
                             // Могут быть и другие поля, в зависимости от ошибки
}

// --- Модели данных (Запросы и Ответы) ---

// Сумма
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Amount {
    pub value: String,    // Сумма в виде строки (например, "100.00")
    pub currency: String, // Код валюты (например, "RUB")
}

// Данные для подтверждения платежа (в запросе)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfirmationRequest {
    #[serde(rename = "type")]
    pub confirmation_type: String, // Тип подтверждения ("redirect")
    pub return_url: String, // URL для возврата пользователя
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce: Option<bool>, // Для управления 3-D Secure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>, // Язык интерфейса платежной формы (ru_RU, en_US)
}

// Данные о способе оплаты (в запросе)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentMethodData {
    #[serde(rename = "type")]
    pub payment_method_type: String, // Тип способа оплаты ("bank_card", "sbp", etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<CardData>, // Данные карты (только при PCI DSS!)
    // Другие поля для других способов оплаты (login для SberPay, phone для mobile_balance, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

// Данные банковской карты (для запроса при PCI DSS - использовать с ОСТОРОЖНОСТЬЮ!)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CardData {
    pub number: String,
    pub expiry_year: String,
    pub expiry_month: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csc: Option<String>, // CVC/CVV
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder: Option<String>, // Имя держателя карты
}

// Запрос на создание платежа
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreatePaymentRequest {
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_data: Option<PaymentMethodData>, // Если не указано, выбор на стороне YooKassa
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<ConfirmationRequest>, // Обязательно, если не используется payment_token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<bool>, // true для одностадийной оплаты (по умолчанию false)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub save_payment_method: Option<bool>, // Сохранить способ оплаты для автоплатежей
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>, // Произвольные метаданные (ключ-значение)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>, // Данные для чека 54-ФЗ
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_token: Option<String>, // Токен от Checkout.js или Mobile SDK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method_id: Option<String>, // ID сохраненного способа оплаты
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>, // IP адрес пользователя
                                   // ... другие поля по необходимости (airline, transfers, deal, etc.)
}

// Запрос на подтверждение (capture) платежа
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CapturePaymentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Amount>, // Для частичного списания
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Receipt>, // Чек для 54-ФЗ при подтверждении
                                  // ... другие поля по необходимости (transfers, deal, etc.)
}

// --- Структуры ответа API ---

// Статус платежа
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    WaitingForCapture,
    Succeeded,
    Canceled,
}

// Детали подтверждения (в ответе)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfirmationResponse {
    #[serde(rename = "type")]
    pub confirmation_type: String, // "redirect", "external", "qr", "embedded", "mobile_application"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_url: Option<String>, // URL для редиректа пользователя
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>, // URL для возврата пользователя (из запроса)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforce: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_data: Option<String>, // Для QR кода
}

// Получатель платежа
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Recipient {
    pub account_id: String,
    pub gateway_id: String,
}

// Данные карты в ответе
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CardDetails {
    pub first6: Option<String>,
    pub last4: String,
    pub expiry_year: String,
    pub expiry_month: String,
    pub card_type: String, // "MasterCard", "Visa", "Mir", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_country: Option<String>, // "RU"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>, // "Sberbank"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>, // "mir_pay", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_product: Option<CardProduct>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CardProduct {
    pub code: Option<String>,
    pub name: Option<String>,
}

// Способ оплаты в ответе
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: String, // "bank_card", "yoo_money", "sbp", etc.
    pub id: String,
    pub saved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>, // "Bank card *4444"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<CardDetails>, // Если тип bank_card
    // ... другие поля для других способов оплаты
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>, // Для YooMoney
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>, // Для mobile_balance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbp_operation_id: Option<String>, // Для SBP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_bank_details: Option<PayerBankDetails>, // Для SBP
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PayerBankDetails {
    pub bic: Option<String>,
    pub bank_id: Option<String>,
}

// Детали отмены
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CancellationDetails {
    pub party: String,  // "yookassa", "merchant", "payment_network"
    pub reason: String, // "expired_on_confirmation", "payment_rejected", etc.
}

// 3-D Secure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ThreeDSecure {
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_relevant: Option<bool>,
    // ... другие возможные поля
}

// Детали авторизации
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizationDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rrn: Option<String>, // Retrieval Reference Number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_code: Option<String>, // Код авторизации
    #[serde(skip_serializing_if = "Option::is_none")]
    pub three_d_secure: Option<ThreeDSecure>,
}

// Полный объект платежа (ответ)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payment {
    pub id: String, // Идентификатор платежа
    pub status: PaymentStatus,
    pub amount: Amount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub income_amount: Option<Amount>, // Сумма за вычетом комиссии
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub recipient: Recipient,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<PaymentMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>, // ISO 8601 timestamp
    pub created_at: String, // ISO 8601 timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>, // ISO 8601 timestamp (для waiting_for_capture)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<ConfirmationResponse>,
    pub test: bool,       // Тестовый платеж?
    pub paid: bool,       // true если status = succeeded или waiting_for_capture
    pub refundable: bool, // Можно ли вернуть средства?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refunded_amount: Option<Amount>, // Сумма возвращенных средств
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_registration: Option<String>, // Статус регистрации чека ("pending", "succeeded", "canceled")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation_details: Option<CancellationDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<AuthorizationDetails>,
    // ... другие поля (transfers, deal, merchant_customer_id, etc.)
}

// Список платежей (ответ)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentList {
    #[serde(rename = "type")]
    pub list_type: String, // "list"
    pub items: Vec<Payment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>, // Указатель для пагинации
}

// --- Структуры для чеков 54-ФЗ ---
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inn: Option<String>, // ИНН (10 или 12 цифр)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>, // В формате ITU-T E.164
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptItem {
    pub description: String, // Наименование товара/услуги
    pub quantity: String,    // Количество/объем (строка)
    pub amount: Amount,      // Стоимость товара с учетом количества и скидок
    pub vat_code: i32,       // Ставка НДС (см. документацию YooKassa)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_mode: Option<String>, // Признак способа расчета
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_subject: Option<String>, // Признак предмета расчета
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_of_origin_code: Option<String>, // Код страны происхождения товара (ISO 3166-1 alpha-2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customs_declaration_number: Option<String>, // Номер таможенной декларации
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excise: Option<String>, // Сумма акциза с копейками
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_code: Option<String>, // Код товара (для маркировки)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark_quantity: Option<ReceiptMarkQuantity>, // Дробное количество маркированного товара
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_subject_industry_details: Option<Vec<PaymentSubjectIndustryDetails>>, // Отраслевой реквизит предмета расчета
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_mark: Option<String>, // Код маркировки товара (для ФФД 1.2)
                                      // ... другие поля для чеков
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptMarkQuantity {
    pub numerator: i32,
    pub denominator: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentSubjectIndustryDetails {
    pub federal_id: String,      // 001-008
    pub document_date: String,   // ГГГГ-ММ-ДД
    pub document_number: String, // до 32 символов
    pub value: String,           // до 256 символов
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Receipt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<ReceiptCustomer>,
    pub items: Vec<ReceiptItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tax_system_code: Option<i32>, // Код системы налогообложения
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_industry_details: Option<Vec<ReceiptIndustryDetails>>, // Отраслевой реквизит чека
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_operational_details: Option<ReceiptOperationalDetails>, // Операционный реквизит чека
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptIndustryDetails {
    pub federal_id: String,      // 001-008
    pub document_date: String,   // ГГГГ-ММ-ДД
    pub document_number: String, // до 32 символов
    pub value: String,           // до 256 символов
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiptOperationalDetails {
    pub operation_id: i32,  // от 0 до 255
    pub value: String,      // до 64 символов
    pub created_at: String, // ISO 8601 timestamp
}

// --- Клиент YooKassa ---

#[derive(Clone)]
pub struct YooKassaClient {
    client: ReqwestClient,
    shop_id: String,
    secret_key: String,
    base_url: String,
}

impl YooKassaClient {
    /// Создает новый клиент YooKassa API.
    ///
    /// # Arguments
    ///
    /// * `shop_id` - Идентификатор вашего магазина.
    /// * `secret_key` - Секретный ключ вашего магазина.
    pub fn new(shop_id: String, secret_key: String) -> Self {
        YooKassaClient {
            client: ReqwestClient::builder()
                .timeout(Duration::from_secs(30)) // Таймаут по умолчанию
                .build()
                .expect("Не удалось создать HTTP клиент"), // Паника здесь допустима при инициализации
            shop_id,
            secret_key,
            base_url: YOOKASSA_API_BASE_URL.to_string(),
        }
    }

    /// Устанавливает кастомный базовый URL (для тестирования или прокси).
    pub fn set_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    // Внутренний метод для отправки запросов
    async fn send_request<T: Serialize>(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<&T>,
        idempotency_key_required: bool,
    ) -> Result<Response, YooKassaError> {
        let url = format!("{}{}", self.base_url, endpoint);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json")); // Явно указываем, что ждем JSON

        // Генерируем ключ идемпотентности, если он нужен
        if idempotency_key_required {
            let idempotency_key = Uuid::new_v4().to_string();
            headers.insert(
                IDEMPOTENCE_KEY_HEADER,
                HeaderValue::from_str(&idempotency_key)?,
            );
        }

        let mut request_builder = self
            .client
            .request(method, url)
            .basic_auth(&self.shop_id, Some(&self.secret_key))
            .headers(headers);

        if let Some(payload) = body {
            request_builder = request_builder.json(payload);
            // println!("Request Body: {}", serde_json::to_string_pretty(&payload).unwrap_or_default()); // Для отладки
        }

        let response = request_builder.send().await?;
        // println!("Response Status: {}", response.status()); // Для отладки

        Ok(response)
    }

    // Внутренний метод для обработки ответа и парсинга JSON
    async fn process_response<R: for<'de> Deserialize<'de>>(
        &self,
        response: Response,
    ) -> Result<R, YooKassaError> {
        let status = response.status();
        if status.is_success() {
            // println!("Response Body (Raw): {}", response.text().await?); // Для отладки
            // Необходимо клонировать response, чтобы можно было прочитать тело дважды
            // let text_body = response.text().await?;
            // println!("Response Body: {}", text_body);
            // serde_json::from_str(&text_body).map_err(YooKassaError::Serde)
            response.json::<R>().await.map_err(YooKassaError::Reqwest) // Используем Reqwest ошибку для JSON парсинга ответа
        } else {
            let body_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Не удалось прочитать тело ответа".to_string());
            // Пытаемся распарсить как ошибку API
            let api_error_details: Option<YooKassaApiError> = serde_json::from_str(&body_text).ok();
            Err(YooKassaError::ApiError {
                status,
                message: body_text,
                error_details: api_error_details,
            })
        }
    }

    /// Создает новый платеж.
    ///
    /// # Arguments
    ///
    /// * `request` - Данные для создания платежа.
    pub async fn create_payment(
        &self,
        request: &CreatePaymentRequest,
    ) -> Result<Payment, YooKassaError> {
        let response = self
            .send_request(
                Method::POST,
                "payments",
                Some(request),
                true, // Требуется ключ идемпотентности
            )
            .await?;
        self.process_response(response).await
    }

    /// Получает информацию о конкретном платеже.
    ///
    /// # Arguments
    ///
    /// * `payment_id` - Идентификатор платежа.
    pub async fn get_payment(&self, payment_id: &str) -> Result<Payment, YooKassaError> {
        let endpoint = format!("payments/{}", payment_id);
        let response = self.send_request::<()>( // Тип тела не важен для GET
            Method::GET,
            &endpoint,
            None,
            false // Не требуется ключ идемпотентности
        ).await?;
        self.process_response(response).await
    }

    /// Подтверждает (списывает) платеж, находящийся в статусе `waiting_for_capture`.
    ///
    /// # Arguments
    ///
    /// * `payment_id` - Идентификатор платежа.
    /// * `request` - Опциональные данные для подтверждения (например, сумма для частичного списания).
    ///              Если None, подтверждается вся сумма.
    pub async fn capture_payment(
        &self,
        payment_id: &str,
        request: Option<&CapturePaymentRequest>,
    ) -> Result<Payment, YooKassaError> {
        let endpoint = format!("payments/{}/capture", payment_id);
        // YooKassa ожидает пустой JSON объект {}, если request is None
        let default_body = CapturePaymentRequest::default();
        let body_to_send = request.unwrap_or(&default_body);

        let response = self
            .send_request(
                Method::POST,
                &endpoint,
                Some(body_to_send),
                true, // Требуется ключ идемпотентности
            )
            .await?;
        self.process_response(response).await
    }

    /// Отменяет платеж, находящийся в статусе `waiting_for_capture`.
    ///
    /// # Arguments
    ///
    /// * `payment_id` - Идентификатор платежа.
    pub async fn cancel_payment(&self, payment_id: &str) -> Result<Payment, YooKassaError> {
        let endpoint = format!("payments/{}/cancel", payment_id);
        // API ожидает пустой JSON объект {} в теле запроса
        let empty_body: serde_json::Value = serde_json::json!({});
        let response = self
            .send_request(
                Method::POST,
                &endpoint,
                Some(&empty_body),
                true, // Требуется ключ идемпотентности
            )
            .await?;
        self.process_response(response).await
    }

    /// Получает список платежей с возможностью фильтрации и пагинации.
    ///
    /// # Arguments
    ///
    /// * `params` - Опциональные параметры для фильтрации и пагинации (например, `limit`, `status`, `created_at_gte`, `cursor`).
    ///            Пример: `&[("limit", "10"), ("status", "succeeded")]`
    pub async fn list_payments(
        &self,
        params: Option<&[(&str, &str)]>,
    ) -> Result<PaymentList, YooKassaError> {
        let url = format!("{}payments", self.base_url);
        let mut request_builder = self
            .client
            .get(url)
            .basic_auth(&self.shop_id, Some(&self.secret_key))
            .header(ACCEPT, HeaderValue::from_static("application/json"));

        if let Some(query_params) = params {
            request_builder = request_builder.query(query_params);
        }

        let response = request_builder.send().await?;
        self.process_response(response).await
    }
}

// --- Пример использования ---
// Этот код нужно будет поместить в ваш `main.rs` или тесты

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // ВАЖНО: Никогда не храните ключи прямо в коде в реальных приложениях!
//     // Используйте переменные окружения, конфигурационные файлы или секрет-менеджеры.
//     let shop_id = std::env::var("YOOKASSA_SHOP_ID").expect("Нужно установить YOOKASSA_SHOP_ID");
//     let secret_key = std::env::var("YOOKASSA_SECRET_KEY").expect("Нужно установить YOOKASSA_SECRET_KEY");
//     // Убедитесь, что используете ТЕСТОВЫЕ ключи для тестирования!

//     let client = YooKassaClient::new(shop_id, secret_key);

//     // 1. Создание платежа
//     println!("Создание платежа...");
//     let payment_request = CreatePaymentRequest {
//         amount: Amount {
//             value: "10.00".to_string(), // Сумма 10 рублей
//             currency: "RUB".to_string(),
//         },
//         confirmation: Some(ConfirmationRequest {
//             confirmation_type: "redirect".to_string(),
//             // Укажите ваш реальный URL для возврата
//             return_url: "https://www.example.com/return_url".to_string(),
//             enforce: None,
//             locale: Some("ru_RU".to_string())
//         }),
//         capture: Some(true), // Сразу списать средства (одностадийный платеж)
//         description: Some("Тестовый заказ №123".to_string()),
//         metadata: Some(serde_json::json!({ "order_id": "123xyz" })),
//         payment_method_data: None, // Даем пользователю выбрать способ оплаты на стороне YooKassa
//         save_payment_method: None,
//         receipt: None, // Добавьте данные чека, если нужно
//         payment_token: None,
//         payment_method_id: None,
//         client_ip: None,
//     };

//     match client.create_payment(&payment_request).await {
//         Ok(payment) => {
//             println!("Платеж успешно создан: ID = {}", payment.id);
//             println!("Статус: {:?}", payment.status);

//             if let Some(confirmation) = payment.confirmation {
//                 if let Some(confirmation_url) = confirmation.confirmation_url {
//                     println!("Перенаправьте пользователя на: {}", confirmation_url);
//                     // --- Здесь ваш код должен перенаправить пользователя ---
//                     // --- Пользователь оплачивает ---
//                     // --- Пользователь возвращается на ваш return_url ---

//                     // 2. Проверка статуса платежа после возврата пользователя (или через webhook)
//                     println!("\nПроверка статуса платежа {}...", payment.id);
//                     // Небольшая пауза для имитации времени на оплату
//                     // В реальном приложении ждите webhook или проверяйте статус, когда пользователь вернется
//                     tokio::time::sleep(Duration::from_secs(15)).await;

//                     match client.get_payment(&payment.id).await {
//                         Ok(updated_payment) => {
//                             println!("Получен обновленный статус: {:?}", updated_payment.status);
//                             println!("Оплачен (paid): {}", updated_payment.paid);
//                             if updated_payment.status == PaymentStatus::Succeeded {
//                                 println!("Платеж успешно завершен!");
//                                 // Здесь можно выдать товар/услугу
//                             } else if updated_payment.status == PaymentStatus::Canceled {
//                                 println!("Платеж отменен.");
//                                 if let Some(details) = updated_payment.cancellation_details {
//                                     println!("Причина отмены: {} ({})", details.reason, details.party);
//                                 }
//                             } else {
//                                 println!("Платеж все еще в статусе: {:?}", updated_payment.status);
//                             }
//                             // Можно распечатать весь объект для деталей
//                             // println!("Детали платежа: {:#?}", updated_payment);
//                         }
//                         Err(e) => eprintln!("Ошибка при получении статуса платежа: {}", e),
//                     }
//                 } else {
//                     eprintln!("В ответе не найден confirmation_url для редиректа.");
//                 }
//             } else {
//                 eprintln!("В ответе не найден объект confirmation.");
//             }
//         }
//         Err(e) => {
//             eprintln!("Ошибка при создании платежа: {}", e);
//             if let YooKassaError::ApiError { status: _, message: _, error_details: Some(details) } = e {
//                  eprintln!("Детали ошибки API: {:#?}", details);
//             }
//         }
//     }

//     // 3. Пример получения списка платежей
//     println!("\nПолучение списка последних 5 платежей...");
//     match client.list_payments(Some(&[("limit", "5")])).await {
//         Ok(list) => {
//             println!("Получено {} платежей.", list.items.len());
//             for payment in list.items {
//                 println!(" - ID: {}, Статус: {:?}, Сумма: {} {}",
//                     payment.id, payment.status, payment.amount.value, payment.amount.currency);
//             }
//             if let Some(cursor) = list.next_cursor {
//                  println!("Есть следующая страница, курсор: {}", cursor);
//             }
//         }
//         Err(e) => eprintln!("Ошибка при получении списка платежей: {}", e),
//     }

//     Ok(())
// }
