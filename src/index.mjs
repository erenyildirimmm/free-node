import { createServer } from "http";
import { parse } from "url";

/**
 * ============================================
 * CONFIG - Yapılandırma Katmanı
 * ============================================
 *
 * Bu bölümde uygulamanın tüm ayarları toplanır.
 * Neden ayrı bir config?
 * - Ortam değişkenlerinden (production, development) ayarları alabiliriz
 * - Tek bir yerden tüm ayarları yönetiriz
 * - Test ortamında farklı ayarlar kullanabiliriz
 */
const config = {
  port: process.env.PORT || 3000, // PORT env var yoksa 3000 kullan
  cors: {
    origin: process.env.CORS_ORIGIN || "*", // CORS hangi origin'lere izin verecek
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    headers: ["Content-Type", "Authorization"], // İzin verilen header'lar
  },
};

/**
 * ============================================
 * UTILS - Yardımcı Fonksiyonlar
 * ============================================
 *
 * Bu sınıf HTTP response'larını standart formatta göndermek için kullanılır.
 * Neden ayrı bir sınıf?
 * - DRY (Don't Repeat Yourself) prensibi
 * - Tüm response'lar aynı formatta olur
 * - Değişiklik yapmak kolaylaşır (tek yerden)
 */
class ResponseHelper {
  /**
   * Genel response gönderme metodu
   * @param {http.ServerResponse} res - HTTP response objesi
   * @param {number} statusCode - HTTP status code (200, 404, 500 vs.)
   * @param {object} data - Gönderilecek veri
   * @param {object} headers - Ek header'lar (opsiyonel)
   *
   * writeHead: HTTP response header'larını yazar
   * end: Response'u bitirir ve body'yi gönderir
   */
  static send(res, statusCode, data, headers = {}) {
    const defaultHeaders = {
      "Content-Type": "application/json", // JSON formatında gönderiyoruz
      ...headers, // Ek header'lar varsa ekle
    };

    res.writeHead(statusCode, defaultHeaders);
    res.end(JSON.stringify(data)); // Objeyi JSON string'e çevir
  }

  /**
   * Başarılı response gönderme
   * Standart format: { success: true, data: ... }
   *
   * Neden bu format?
   * - Frontend'de response'un başarılı olup olmadığını kolay kontrol ederiz
   * - Tutarlı API response yapısı
   */
  static success(res, data, statusCode = 200) {
    this.send(res, statusCode, { success: true, data });
  }

  /**
   * Hata response gönderme
   * Standart format: { success: false, error: "...", errors: [...] }
   *
   * @param {http.ServerResponse} res
   * @param {string} message - Hata mesajı
   * @param {number} statusCode - HTTP status code
   * @param {array} errors - Validation hataları gibi detaylı hatalar (opsiyonel)
   */
  static error(res, message, statusCode = 500, errors = null) {
    const response = { success: false, error: message };
    if (errors) response.errors = errors; // Validation hataları varsa ekle
    this.send(res, statusCode, response);
  }

  /**
   * 404 Not Found response
   * Kaynak bulunamadığında kullanılır
   */
  static notFound(res, message = "Resource not found") {
    this.error(res, message, 404);
  }

  /**
   * 400 Bad Request response
   * Geçersiz request (validation hatası vs.) için kullanılır
   */
  static badRequest(res, message = "Bad request", errors = null) {
    this.error(res, message, 400, errors);
  }
}

/**
 * ============================================
 * REQUEST PARSER - Request İşleme
 * ============================================
 *
 * Bu sınıf HTTP request'lerinden veri çıkarmak için kullanılır.
 * Node.js'de request'ler stream olarak gelir, bunları parse etmemiz gerekir.
 */
class RequestParser {
  /**
   * Request body'sini parse etme
   *
   * Node.js'de request body bir stream'dir. Stream'den veri okumak için
   * event listener'lar kullanırız:
   * - 'data': Her veri parçası geldiğinde tetiklenir
   * - 'end': Tüm veri geldiğinde tetiklenir
   * - 'error': Hata olduğunda tetiklenir
   *
   * Promise kullanma nedeni: Async işlem, await ile kullanabilmek için
   *
   * @returns {Promise<object>} Parse edilmiş JSON objesi
   */
  static async parseBody(req) {
    return new Promise((resolve, reject) => {
      // Content-Type kontrolü - sadece JSON kabul ediyoruz
      const contentType = req.headers["content-type"] || "";

      if (!contentType.includes("application/json")) {
        return resolve({}); // JSON değilse boş obje döndür
      }

      let body = "";
      const maxSize = 1024 * 1024; // 1MB limit (DoS saldırılarına karşı)
      let size = 0;

      // Stream'den veri okuma
      req.on("data", (chunk) => {
        size += chunk.length;
        // Güvenlik: Çok büyük body'leri reddet
        if (size > maxSize) {
          reject(new Error("Request body too large"));
          return;
        }
        // Buffer'ı string'e çevir ve birleştir
        body += chunk.toString();
      });

      // Tüm veri geldiğinde
      req.on("end", () => {
        try {
          // JSON string'i objeye çevir
          resolve(body ? JSON.parse(body) : {});
        } catch (error) {
          // Geçersiz JSON formatı
          reject(new Error("Invalid JSON format"));
        }
      });

      // Hata durumu
      req.on("error", reject);
    });
  }

  /**
   * URL'i parse etme
   * Node.js'in built-in 'url' modülünü kullanarak:
   * - pathname: /todos/123 gibi path
   * - query: ?completed=true gibi query parametreleri
   * - search: ?completed=true string'i
   *
   * @param {string} url - Parse edilecek URL
   * @returns {object} { pathname, query, search }
   */
  static parseUrl(url) {
    const parsed = parse(url, true); // true = query string'i de parse et
    return {
      pathname: parsed.pathname, // /todos/123
      query: parsed.query, // { completed: 'true' }
      search: parsed.search, // ?completed=true
    };
  }

  /**
   * Route parametrelerini çıkarma
   *
   * Express'teki :id gibi parametreleri çıkarırız.
   * Örnek:
   *   pattern: '/todos/:id'
   *   pathname: '/todos/123'
   *   Sonuç: { id: '123' }
   *
   * Nasıl çalışır?
   * 1. Pattern ve pathname'i '/' ile böleriz
   * 2. Her parçayı karşılaştırırız
   * 3. ':' ile başlayan kısımlar parametredir
   * 4. Eşleşme varsa parametreleri döndürürüz
   *
   * @param {string} pathname - Gerçek path (/todos/123)
   * @param {string} routePattern - Route pattern (/todos/:id)
   * @returns {object|null} Parametreler veya null (eşleşme yoksa)
   */
  static extractParams(pathname, routePattern) {
    const patternParts = routePattern.split("/"); // ['', 'todos', ':id']
    const pathParts = pathname.split("/"); // ['', 'todos', '123']
    const params = {};

    // Parça sayıları eşleşmeli
    if (patternParts.length !== pathParts.length) {
      return null; // Eşleşme yok
    }

    // Her parçayı kontrol et
    for (let i = 0; i < patternParts.length; i++) {
      // ':' ile başlıyorsa bu bir parametredir
      if (patternParts[i].startsWith(":")) {
        const paramName = patternParts[i].slice(1); // ':' kısmını çıkar -> 'id'
        params[paramName] = pathParts[i]; // Değeri al -> '123'
      }
      // Normal string ise tam eşleşme olmalı
      else if (patternParts[i] !== pathParts[i]) {
        return null; // Eşleşme yok
      }
    }

    return params; // { id: '123' }
  }
}

/**
 * ============================================
 * MIDDLEWARE - Ara Katman İşlemleri
 * ============================================
 *
 * Middleware nedir?
 * Request handler'a ulaşmadan önce çalışan fonksiyonlardır.
 *
 * Kullanım alanları:
 * - CORS ayarları
 * - Authentication (kimlik doğrulama)
 * - Logging (istekleri kaydetme)
 * - Body parsing (request body'sini parse etme)
 * - Rate limiting (istek sınırlama)
 *
 * Express'te app.use() ile kullanılır, biz manuel yapıyoruz.
 */
class Middleware {
  /**
   * CORS (Cross-Origin Resource Sharing) Middleware
   *
   * CORS nedir?
   * Farklı origin'lerden (domain, port) gelen isteklere izin verme.
   * Örnek: localhost:3000'den localhost:8080'e istek yapmak.
   *
   * Browser security: Browser varsayılan olarak cross-origin istekleri engeller.
   * CORS header'ları ile izin veririz.
   *
   * OPTIONS request nedir?
   * Browser önce OPTIONS request gönderir (preflight), sonra gerçek request'i gönderir.
   *
   * @returns {boolean} true = request burada bitti (OPTIONS), false = devam et
   */
  static cors(req, res) {
    // CORS header'larını ekle
    res.setHeader("Access-Control-Allow-Origin", config.cors.origin);
    res.setHeader(
      "Access-Control-Allow-Methods",
      config.cors.methods.join(", ")
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      config.cors.headers.join(", ")
    );
    res.setHeader("Access-Control-Max-Age", "86400"); // 24 saat cache

    // Preflight request (OPTIONS) - browser'a izin verildiğini söyle
    if (req.method === "OPTIONS") {
      ResponseHelper.send(res, 200, {});
      return true; // Request'i burada bitir, handler'a gitme
    }
    return false; // Devam et, handler'a git
  }

  /**
   * Body Parser Middleware
   *
   * Request body'sini parse edip req.body'ye ekler.
   * Express'te express.json() bunu yapar.
   *
   * Neden middleware?
   * - Her handler'da tekrar yazmamak için
   * - Merkezi bir yerden yönetmek için
   *
   * @throws {Error} Parse hatası durumunda
   */
  static async bodyParser(req) {
    try {
      // RequestParser'ı kullanarak body'yi parse et
      req.body = await RequestParser.parseBody(req);
    } catch (error) {
      throw new Error(`Body parsing failed: ${error.message}`);
    }
  }

  /**
   * Request Logger Middleware
   *
   * Her request'i konsola yazdırır.
   * Production'da genelde Winston, Morgan gibi kütüphaneler kullanılır.
   *
   * Neden önemli?
   * - Debug için
   * - Monitoring için
   * - Security audit için
   */
  static async requestLogger(req) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.url}`);
  }
}

/**
 * ============================================
 * SERVICE LAYER - İş Mantığı Katmanı
 * ============================================
 *
 * Service Layer Pattern nedir?
 * Business logic'i (iş mantığı) controller'dan ayırırız.
 *
 * Neden ayrı?
 * - Controller sadece HTTP ile ilgilenir (request/response)
 * - Service iş mantığı ile ilgilenir (veri işleme, validation)
 * - Test etmek kolaylaşır (HTTP olmadan test edebiliriz)
 * - Reusability (başka yerlerde de kullanabiliriz)
 *
 * Gerçek uygulamada:
 * - Database işlemleri burada olur
 * - External API çağrıları burada olur
 * - Complex business rules burada olur
 */
class TodoService {
  constructor() {
    // In-memory database (gerçek uygulamada PostgreSQL, MongoDB vs. kullanılır)
    this.todos = [
      {
        id: 1,
        title: "Node.js öğren",
        completed: false,
        createdAt: new Date().toISOString(),
      },
      {
        id: 2,
        title: "Express öğren",
        completed: false,
        createdAt: new Date().toISOString(),
      },
    ];
    this.nextId = 3; // Auto-increment ID
  }

  /**
   * Tüm todo'ları getir
   *
   * @param {object} filters - Filtreleme parametreleri
   * @param {string} filters.completed - 'true' veya 'false'
   * @param {string} filters.search - Arama terimi
   * @returns {array} Filtrelenmiş todo listesi
   */
  findAll(filters = {}) {
    let result = [...this.todos]; // Shallow copy (referans kopyalamak yerine)

    // Completed filter
    if (filters.completed !== undefined) {
      const isCompleted =
        filters.completed === "true" || filters.completed === true;
      result = result.filter((todo) => todo.completed === isCompleted);
    }

    // Search filter
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      result = result.filter((todo) =>
        todo.title.toLowerCase().includes(searchLower)
      );
    }

    return result;
  }

  /**
   * ID'ye göre todo bul
   *
   * @param {string|number} id - Todo ID'si
   * @returns {object} Todo objesi
   * @throws {Error} Todo bulunamazsa
   */
  findById(id) {
    const todo = this.todos.find((t) => t.id === parseInt(id));
    if (!todo) {
      throw new Error("Todo not found");
    }
    return todo;
  }

  /**
   * Yeni todo oluştur
   *
   * Validation burada yapılır (Service Layer sorumluluğu)
   *
   * @param {object} data - Todo verisi
   * @param {string} data.title - Todo başlığı (zorunlu)
   * @param {boolean} data.completed - Tamamlanma durumu (opsiyonel)
   * @returns {object} Oluşturulan todo
   * @throws {Error} Validation hatası durumunda
   */
  create(data) {
    // Validation: Title kontrolü
    if (!data.title || data.title.trim().length === 0) {
      throw new Error("Title is required and cannot be empty");
    }

    // Validation: Maksimum uzunluk kontrolü
    if (data.title.length > 200) {
      throw new Error("Title cannot exceed 200 characters");
    }

    // Yeni todo objesi oluştur
    const newTodo = {
      id: this.nextId++,
      title: data.title.trim(), // Başındaki/sonundaki boşlukları temizle
      completed: data.completed || false,
      createdAt: new Date().toISOString(), // ISO 8601 formatı
      updatedAt: new Date().toISOString(),
    };

    this.todos.push(newTodo);
    return newTodo;
  }

  /**
   * Todo güncelle
   *
   * @param {string|number} id - Todo ID'si
   * @param {object} data - Güncellenecek veriler
   * @returns {object} Güncellenmiş todo
   * @throws {Error} Todo bulunamazsa veya validation hatası
   */
  update(id, data) {
    const todoIndex = this.todos.findIndex((t) => t.id === parseInt(id));

    if (todoIndex === -1) {
      throw new Error("Todo not found");
    }

    // Validation: Title güncelleniyorsa kontrol et
    if (data.title !== undefined) {
      if (!data.title || data.title.trim().length === 0) {
        throw new Error("Title cannot be empty");
      }
      if (data.title.length > 200) {
        throw new Error("Title cannot exceed 200 characters");
      }
    }

    // Spread operator ile merge et (immutable update)
    const updatedTodo = {
      ...this.todos[todoIndex], // Mevcut todo
      ...data, // Yeni veriler
      id: this.todos[todoIndex].id, // ID değiştirilemez (güvenlik)
      updatedAt: new Date().toISOString(), // Güncelleme zamanı
    };

    this.todos[todoIndex] = updatedTodo;
    return updatedTodo;
  }

  /**
   * Todo sil
   *
   * @param {string|number} id - Todo ID'si
   * @returns {object} Silme mesajı
   * @throws {Error} Todo bulunamazsa
   */
  delete(id) {
    const todoIndex = this.todos.findIndex((t) => t.id === parseInt(id));

    if (todoIndex === -1) {
      throw new Error("Todo not found");
    }

    // Array'den çıkar
    this.todos.splice(todoIndex, 1);
    return { message: "Todo deleted successfully" };
  }
}

/**
 * ============================================
 * CONTROLLER - Request/Response Yönetimi
 * ============================================
 *
 * Controller Pattern nedir?
 * HTTP request/response işlemlerini yönetir.
 *
 * Sorumlulukları:
 * - Request'ten veri almak (params, query, body)
 * - Service'i çağırmak
 * - Response göndermek
 * - Hata yönetimi
 *
 * Neden Service'ten ayrı?
 * - Separation of Concerns: HTTP ile iş mantığı ayrı
 * - Test: Controller'ı mock request/response ile test edebiliriz
 * - Flexibility: Aynı service'i farklı controller'larda kullanabiliriz
 */
class TodoController {
  constructor() {
    // Service instance'ı oluştur
    // Dependency Injection: Service'i dışarıdan da alabiliriz (test için)
    this.service = new TodoService();
  }

  /**
   * GET /todos - Tüm todo'ları listele
   *
   * @param {object} req - HTTP request (query parametreleri içerir)
   * @param {object} res - HTTP response
   */
  async getAll(req, res) {
    try {
      // Service'i çağır (business logic)
      const todos = this.service.findAll(req.query);
      // Başarılı response gönder
      ResponseHelper.success(res, todos);
    } catch (error) {
      // Hata durumunda
      ResponseHelper.error(res, error.message, 500);
    }
  }

  /**
   * GET /todos/:id - Tek todo getir
   *
   * @param {object} req - HTTP request (params.id içerir)
   * @param {object} res - HTTP response
   */
  async getById(req, res) {
    try {
      const todo = this.service.findById(req.params.id);
      ResponseHelper.success(res, todo);
    } catch (error) {
      // Hata tipine göre farklı status code
      if (error.message === "Todo not found") {
        ResponseHelper.notFound(res, error.message);
      } else {
        ResponseHelper.error(res, error.message, 500);
      }
    }
  }

  /**
   * POST /todos - Yeni todo oluştur
   *
   * @param {object} req - HTTP request (body içerir)
   * @param {object} res - HTTP response
   */
  async create(req, res) {
    try {
      const todo = this.service.create(req.body);
      // 201 Created status code (yeni kaynak oluşturuldu)
      ResponseHelper.success(res, todo, 201);
    } catch (error) {
      // Validation hatası mı?
      if (
        error.message.includes("required") ||
        error.message.includes("cannot")
      ) {
        ResponseHelper.badRequest(res, error.message);
      } else {
        ResponseHelper.error(res, error.message, 500);
      }
    }
  }

  /**
   * PUT /todos/:id - Todo güncelle
   *
   * @param {object} req - HTTP request (params.id ve body içerir)
   * @param {object} res - HTTP response
   */
  async update(req, res) {
    try {
      const todo = this.service.update(req.params.id, req.body);
      ResponseHelper.success(res, todo);
    } catch (error) {
      // Hata tipine göre farklı response
      if (error.message === "Todo not found") {
        ResponseHelper.notFound(res, error.message);
      } else if (error.message.includes("cannot")) {
        ResponseHelper.badRequest(res, error.message);
      } else {
        ResponseHelper.error(res, error.message, 500);
      }
    }
  }

  /**
   * DELETE /todos/:id - Todo sil
   *
   * @param {object} req - HTTP request (params.id içerir)
   * @param {object} res - HTTP response
   */
  async delete(req, res) {
    try {
      const result = this.service.delete(req.params.id);
      ResponseHelper.success(res, result);
    } catch (error) {
      if (error.message === "Todo not found") {
        ResponseHelper.notFound(res, error.message);
      } else {
        ResponseHelper.error(res, error.message, 500);
      }
    }
  }
}

/**
 * ============================================
 * ROUTER - Route Yönetimi
 * ============================================
 *
 * Router Pattern nedir?
 * URL ve HTTP method'una göre doğru handler'ı bulur.
 *
 * Express'te app.get(), app.post() gibi metodlar bunu yapar.
 * Biz manuel yapıyoruz.
 *
 * Nasıl çalışır?
 * 1. Route'ları kaydederiz (method, pattern, handler)
 * 2. Request geldiğinde route'ları kontrol ederiz
 * 3. Eşleşen route'u buluruz
 * 4. Handler'ı çalıştırırız
 */
class Router {
  constructor() {
    this.routes = []; // Tüm route'lar burada
    this.controller = new TodoController(); // Controller instance'ı
  }

  /**
   * Route kaydetme
   *
   * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
   * @param {string} pattern - Route pattern (/todos/:id)
   * @param {function} handler - Route handler fonksiyonu
   *
   * Örnek:
   *   register('GET', '/todos/:id', (req, res) => {...})
   */
  register(method, pattern, handler) {
    this.routes.push({ method, pattern, handler });
  }

  /**
   * Request için route bulma
   *
   * @param {object} req - HTTP request
   * @param {object} res - HTTP response
   * @returns {function|null} Handler fonksiyonu veya null
   *
   * Algoritma:
   * 1. Request'in method'unu al
   * 2. URL'i parse et
   * 3. Her route'u kontrol et:
   *    - Method eşleşiyor mu?
   *    - Pattern eşleşiyor mu? (parametreleri çıkar)
   * 4. Eşleşen route'un handler'ını döndür
   */
  async match(req, res) {
    const { method, url } = req;
    const { pathname, query } = RequestParser.parseUrl(url);

    // Query parametrelerini req'e ekle (controller'da kullanmak için)
    req.query = query;
    req.pathname = pathname;

    // Tüm route'ları kontrol et
    for (const route of this.routes) {
      // Method eşleşiyor mu?
      if (route.method !== method) continue;

      // Pattern eşleşiyor mu? (parametreleri çıkar)
      const params = RequestParser.extractParams(pathname, route.pattern);

      if (params !== null) {
        // Eşleşme bulundu! Parametreleri req'e ekle
        req.params = params;
        return route.handler; // Handler'ı döndür
      }
    }

    return null; // Eşleşme yok
  }

  /**
   * Route'ları tanımla
   *
   * Express'teki app.get(), app.post() gibi metodların yaptığı işi yapar.
   * Her route için:
   * - HTTP method
   * - URL pattern
   * - Controller metodunu bağla
   */
  setupRoutes() {
    // GET /todos - Tüm todo'ları listele
    this.register("GET", "/todos", (req, res) =>
      this.controller.getAll(req, res)
    );

    // GET /todos/:id - Tek todo getir
    this.register("GET", "/todos/:id", (req, res) =>
      this.controller.getById(req, res)
    );

    // POST /todos - Yeni todo oluştur
    this.register("POST", "/todos", (req, res) =>
      this.controller.create(req, res)
    );

    // PUT /todos/:id - Todo güncelle
    this.register("PUT", "/todos/:id", (req, res) =>
      this.controller.update(req, res)
    );

    // DELETE /todos/:id - Todo sil
    this.register("DELETE", "/todos/:id", (req, res) =>
      this.controller.delete(req, res)
    );
  }
}

/**
 * ============================================
 * APPLICATION - Ana Uygulama
 * ============================================
 *
 * Bu sınıf tüm parçaları bir araya getirir.
 *
 * Request Pipeline (İstek İşleme Akışı):
 * 1. Request gelir
 * 2. CORS middleware çalışır
 * 3. Request logger çalışır
 * 4. Body parser çalışır (POST/PUT/PATCH ise)
 * 5. Router route'u bulur
 * 6. Controller handler çalışır
 * 7. Service business logic'i çalışır
 * 8. Response gönderilir
 *
 * Bu pipeline Express'in arkasında da benzer şekilde çalışır.
 */
class Application {
  constructor() {
    // Router'ı oluştur ve route'ları tanımla
    this.router = new Router();
    this.router.setupRoutes();
  }

  /**
   * HTTP request handler
   *
   * Bu fonksiyon her HTTP request için çağrılır.
   * Node.js'in createServer() metoduna verilir.
   *
   * @param {object} req - HTTP request
   * @param {object} res - HTTP response
   */
  async handleRequest(req, res) {
    try {
      // ============================================
      // MIDDLEWARE PIPELINE
      // ============================================

      // 1. CORS Middleware
      // OPTIONS request'i burada bitirir, diğerleri devam eder
      if (Middleware.cors(req, res)) return;

      // 2. Request Logger Middleware
      // Her request'i konsola yazdır
      await Middleware.requestLogger(req);

      // 3. Body Parser Middleware
      // Sadece body içeren request'ler için (POST, PUT, PATCH)
      if (["POST", "PUT", "PATCH"].includes(req.method)) {
        await Middleware.bodyParser(req);
      }

      // ============================================
      // ROUTING
      // ============================================

      // 4. Route bul ve handler'ı çalıştır
      const handler = await this.router.match(req, res);

      if (handler) {
        // Handler bulundu, çalıştır
        // Handler -> Controller -> Service -> Response
        await handler(req, res);
      } else {
        // Route bulunamadı (404)
        ResponseHelper.notFound(res, "Route not found");
      }
    } catch (error) {
      // Beklenmeyen hatalar için global error handler
      console.error("Application Error:", error);
      ResponseHelper.error(res, "Internal server error", 500);
    }
  }

  /**
   * Server'ı başlat
   *
   * Node.js'in http.createServer() metodunu kullanarak
   * HTTP server oluşturur ve dinlemeye başlar.
   */
  start() {
    // HTTP server oluştur
    // Her request için handleRequest fonksiyonunu çağır
    const server = createServer((req, res) => this.handleRequest(req, res));

    // Port'u dinlemeye başla
    server.listen(config.port, () => {
      console.log(`🚀 Server running on http://localhost:${config.port}`);
      console.log("\n📝 Available endpoints:");
      console.log("  GET    /todos              - List all todos");
      console.log("  GET    /todos?completed=true - Filter by completion");
      console.log("  GET    /todos?search=node   - Search todos");
      console.log("  GET    /todos/:id          - Get single todo");
      console.log("  POST   /todos              - Create new todo");
      console.log("  PUT    /todos/:id          - Update todo");
      console.log("  DELETE /todos/:id          - Delete todo");
      console.log("\n💡 Professional backend architecture with core Node.js");
    });

    // ============================================
    // GRACEFUL SHUTDOWN
    // ============================================
    //
    // Production'da önemli:
    // - SIGTERM: Process manager (PM2, Docker) tarafından gönderilir
    // - SIGINT: Ctrl+C ile gönderilir
    //
    // Neden önemli?
    // - Aktif request'leri bitirmek için zaman verir
    // - Database connection'ları kapatır
    // - Cleanup işlemleri yapar
    //
    // Express'te de bu pattern kullanılır.
    process.on("SIGTERM", () => {
      console.log("\n🛑 SIGTERM received, shutting down gracefully...");
      server.close(() => {
        console.log("✅ Server closed");
        process.exit(0);
      });
    });

    // Ctrl+C için de aynı işlemi yap
    process.on("SIGINT", () => {
      console.log("\n🛑 SIGINT received, shutting down gracefully...");
      server.close(() => {
        console.log("✅ Server closed");
        process.exit(0);
      });
    });
  }
}

/**
 * ============================================
 * APPLICATION START
 * ============================================
 *
 * Uygulamayı başlat.
 * Bu noktada:
 * - Application instance'ı oluşturulur
 * - Router route'ları tanımlanır
 * - Server başlatılır
 * - Request'ler dinlenmeye başlanır
 */
const app = new Application();
app.start();
