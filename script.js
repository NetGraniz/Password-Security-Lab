"use strict";

class StorageService {
  constructor(prefix = "psl") {
    this.prefix = prefix;
    this.defaults = { generated: [], checked: [], favorites: [], templates: [] };
  }

  key(name) {
    return `${this.prefix}:${name}`;
  }

  get(name) {
    try {
      return JSON.parse(localStorage.getItem(this.key(name))) ?? this.defaults[name] ?? [];
    } catch {
      return this.defaults[name] ?? [];
    }
  }

  set(name, value) {
    localStorage.setItem(this.key(name), JSON.stringify(value));
  }

  push(name, item, limit = 50) {
    const list = this.get(name);
    list.unshift({ ...item, createdAt: new Date().toISOString() });
    this.set(name, list.slice(0, limit));
  }

  clear(name) {
    localStorage.removeItem(this.key(name));
  }

  clearAllProjectData() {
    Object.keys(localStorage)
      .filter((key) => key.startsWith(`${this.prefix}:`))
      .forEach((key) => localStorage.removeItem(key));
  }
}

class EntropyCalculator {
  static detect(password) {
    return {
      upper: /[A-ZА-ЯЁ]/.test(password),
      lower: /[a-zа-яё]/.test(password),
      digits: /\d/.test(password),
      special: /[^A-Za-zА-Яа-яЁё0-9]/.test(password)
    };
  }

  static poolSize(flags) {
    let size = 0;
    if (flags.upper) size += 59;
    if (flags.lower) size += 59;
    if (flags.digits) size += 10;
    if (flags.special) size += 32;
    return Math.max(size, 1);
  }

  static theoretical(password) {
    if (!password) return 0;
    return password.length * Math.log2(this.poolSize(this.detect(password)));
  }

  static passphrase(dictionarySize, wordCount, hasDigits, hasSpecial) {
    let entropy = wordCount * Math.log2(dictionarySize);
    if (hasDigits) entropy += Math.log2(100);
    if (hasSpecial) entropy += Math.log2(10);
    return entropy;
  }
}

class PasswordAnalyzer {
  static weakPatterns = [
    "password", "admin", "qwerty", "qwerty123", "password123", "admin123", "welcome", "letmein",
    "iloveyou", "monkey", "dragon", "football", "master", "secret", "пароль", "админ", "привет",
    "любовь", "qwertyйцукен", "йцукен", "123456", "123456789", "111111", "000000"
  ];

  static sequencePatterns = ["qwerty", "йцукен", "asdfgh", "zxcvbn", "123456", "654321", "abcdef", "aaa111"];
  static dictionary = [
    "password", "admin", "welcome", "login", "user", "dragon", "monkey", "master", "football", "iloveyou",
    "secret", "letmein", "пароль", "админ", "привет", "любовь", "секрет", "доступ", "логин",
    "privet", "parol", "admin", "lubov", "sekret", "dostup"
  ];
  static leetWords = ["p@ssw0rd", "pa55word", "adm1n", "s3cret", "l0v3", "qwerty"];

  analyze(password, breach = null) {
    const flags = EntropyCalculator.detect(password);
    const theoreticalEntropy = EntropyCalculator.theoretical(password);
    const lower = password.toLowerCase();
    const weakMatches = PasswordAnalyzer.weakPatterns.filter((pattern) => lower.includes(pattern));
    const sequenceMatches = PasswordAnalyzer.sequencePatterns.filter((pattern) => lower.includes(pattern));
    const dictionaryMatches = PasswordAnalyzer.dictionary.filter((word) => lower.includes(word));
    const leetMatches = PasswordAnalyzer.leetWords.filter((word) => lower.includes(word));
    const hasRepeats = /(.)\1{2,}/u.test(password) || /(.{2,})\1{1,}/u.test(password);
    const dateMatches = this.detectDates(password);
    const penalties = this.penalties({ password, weakMatches, sequenceMatches, dictionaryMatches, leetMatches, hasRepeats, dateMatches, breach });
    const practicalEntropy = Math.max(0, theoreticalEntropy - penalties.total);
    const level = this.level(practicalEntropy);
    const verdict = this.verdict({ password, practicalEntropy, weakMatches, sequenceMatches, dictionaryMatches, leetMatches, hasRepeats, dateMatches, breach });
    return {
      length: password.length,
      flags,
      theoreticalEntropy,
      practicalEntropy,
      weakMatches,
      sequenceMatches,
      dictionaryMatches,
      leetMatches,
      hasRepeats,
      dateMatches,
      penalties,
      level,
      verdict,
      keyRecommendation: this.keyRecommendation(password, verdict, breach),
      recommendations: this.recommendations(password, { weakMatches, sequenceMatches, dictionaryMatches, leetMatches, hasRepeats, dateMatches, breach })
    };
  }

  detectDates(password) {
    const matches = [];
    const years = password.match(/\b(19[9][0-9]|20[0-3][0-9])\b/g) || [];
    matches.push(...years.filter((year) => Number(year) >= 1990 && Number(year) <= 2035));
    const compactDates = password.match(/\b(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[0-2])(19[9][0-9]|20[0-3][0-9])\b/g) || [];
    const dottedDates = password.match(/\b(0?[1-9]|[12][0-9]|3[01])[./-](0?[1-9]|1[0-2])[./-](19[9][0-9]|20[0-3][0-9])\b/g) || [];
    matches.push(...compactDates, ...dottedDates);
    return [...new Set(matches)];
  }

  penalties(data) {
    let total = 0;
    if (data.password.length > 0 && data.password.length < 10) total += 22;
    if (data.password.length > 0 && data.password.length < 15) total += 10;
    total += data.weakMatches.length * 24;
    total += data.sequenceMatches.length * 16;
    total += data.dictionaryMatches.length * 14;
    total += data.leetMatches.length * 18;
    total += data.dateMatches.length * 12;
    if (data.hasRepeats) total += 14;
    if (data.breach?.found) total += 45;
    return { total };
  }

  level(entropy) {
    const score = Math.max(0, Math.min(100, Math.round(entropy * 1.2)));
    if (score < 25) return { name: "Очень слабый", score, color: "var(--danger)" };
    if (score < 45) return { name: "Слабый", score, color: "var(--orange)" };
    if (score < 65) return { name: "Средний", score, color: "var(--yellow)" };
    if (score < 85) return { name: "Хороший", score, color: "var(--green)" };
    return { name: "Отличный", score, color: "var(--blue)" };
  }

  verdict(data) {
    const obviousWeakness = data.weakMatches.length || data.sequenceMatches.length || data.dictionaryMatches.length || data.leetMatches.length || data.dateMatches.length || data.hasRepeats;
    if (!data.password) return "Нет данных";
    if (data.breach?.found || data.password.length < 8 || data.practicalEntropy < 25 || data.weakMatches.length) return "Не использовать";
    if (data.password.length < 12 || obviousWeakness || data.practicalEntropy < 45) return "Слабый";
    if (data.password.length < 15 || data.practicalEntropy < 65) return "Нормальный";
    if (data.practicalEntropy < 90) return "Хороший";
    return "Отличный";
  }

  keyRecommendation(password, verdict, breach) {
    if (!password) return "Введите пароль, чтобы получить оценку.";
    if (breach?.found) return "Немедленно замените пароль: он найден в известных утечках.";
    if (verdict === "Не использовать") return "Создайте новый пароль длиной минимум 15 символов или парольную фразу.";
    if (verdict === "Слабый") return "Увеличьте длину и уберите предсказуемые слова, даты и последовательности.";
    if (verdict === "Нормальный") return "Подойдёт для низкого риска; для важных аккаунтов используйте 16-20+ символов.";
    return "Используйте этот пароль только уникально для одного сервиса и храните его в менеджере паролей.";
  }

  recommendations(password, data) {
    const tips = [];
    if (!password) return ["Введите пароль, чтобы увидеть рекомендации."];
    if (password.length < 15) tips.push("Главное улучшение: увеличьте длину минимум до 15 символов.");
    if (password.length < 20) tips.push("Для критичных аккаунтов лучше 16-20+ символов или фраза из случайных слов.");
    if (data.breach?.found) tips.push("Пароль найден в утечках. Не используйте его даже с изменённым регистром.");
    if (data.weakMatches.length) tips.push(`Уберите известные слабые шаблоны: ${data.weakMatches.join(", ")}.`);
    if (data.sequenceMatches.length) tips.push(`Избегайте клавиатурных и числовых последовательностей: ${data.sequenceMatches.join(", ")}.`);
    if (data.dictionaryMatches.length) tips.push(`Не используйте словарные слова и транслит: ${data.dictionaryMatches.join(", ")}.`);
    if (data.leetMatches.length) tips.push("Простые замены вроде p@ssw0rd хорошо угадываются атакующими.");
    if (data.dateMatches.length) tips.push(`Уберите даты и годы: ${data.dateMatches.join(", ")}.`);
    if (data.hasRepeats) tips.push("Сократите повторяющиеся символы или повторяющиеся блоки.");
    tips.push("Используйте уникальный пароль для каждого сервиса. Повторное использование опаснее, чем отсутствие спецсимвола.");
    tips.push("Спецсимволы полезны как дополнительное усиление, но длина и непредсказуемость важнее.");
    return tips;
  }
}

class CrackTimeEstimator {
  constructor() {
    this.scenarios = [
      { label: "Обычный домашний компьютер", guesses: 1e6 },
      { label: "Мощный игровой компьютер", guesses: 1e9 },
      { label: "Современная видеокарта", guesses: 1e11 },
      { label: "Несколько видеокарт", guesses: 1e13 },
      { label: "Корпоративный кластер", guesses: 1e15 }
    ];
  }

  estimateSeconds(entropy, guessesPerSecond) {
    return Math.pow(2, entropy) / 2 / guessesPerSecond;
  }

  format(seconds) {
    if (!Number.isFinite(seconds)) return "практически бесконечно";
    const units = [["секунд", 60], ["минут", 60], ["часов", 24], ["дней", 30], ["месяцев", 12], ["лет", 1000], ["тысяч лет", 1000], ["миллионов лет", 1000], ["миллиардов лет", Infinity]];
    let value = Math.max(seconds, 0);
    for (const [unit, divider] of units) {
      if (value < divider) return `${this.round(value)} ${unit}`;
      value /= divider;
    }
    return `${this.round(value)} миллиардов лет`;
  }

  round(value) {
    if (value < 1) return value.toFixed(2);
    if (value < 10) return value.toFixed(1);
    return Math.round(value).toLocaleString("ru-RU");
  }

  forEntropy(entropy) {
    return this.scenarios.map((scenario) => ({
      ...scenario,
      seconds: this.estimateSeconds(entropy, scenario.guesses),
      formatted: this.format(this.estimateSeconds(entropy, scenario.guesses))
    }));
  }
}

class SecureRandom {
  randomInt(max) {
    if (!Number.isSafeInteger(max) || max <= 0) throw new Error("Некорректная граница случайного числа");
    const limit = Math.floor(0x100000000 / max) * max;
    const array = new Uint32Array(1);
    do {
      crypto.getRandomValues(array);
    } while (array[0] >= limit);
    return array[0] % max;
  }

  pick(chars) {
    return chars[this.randomInt(chars.length)];
  }

  shuffle(chars) {
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = this.randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars;
  }
}

class PasswordGenerator {
  constructor() {
    this.random = new SecureRandom();
    this.upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    this.lower = "abcdefghijkmnopqrstuvwxyz";
    this.digits = "23456789";
    this.special = "!@#$%^&*_-+=?";
    this.similar = "Il1O0";
    this.ambiguous = "{}[]()/\\'\"`~,;:.<>";
  }

  clean(chars, options) {
    let value = chars;
    if (options.excludeSimilar) value = [...value].filter((char) => !this.similar.includes(char)).join("");
    if (options.excludeAmbiguous) value = [...value].filter((char) => !this.ambiguous.includes(char)).join("");
    return value;
  }

  sets(options) {
    const sets = [];
    if (options.upper) sets.push(this.clean(this.upper, options));
    if (options.lower) sets.push(this.clean(this.lower, options));
    if (options.digits) sets.push(this.clean(this.digits, options));
    if (options.special) sets.push(this.clean(this.special, options));
    return sets.filter(Boolean);
  }

  generate(options) {
    const sets = this.sets(options);
    if (!sets.length) return { value: "", adjustedLength: options.length };
    const adjustedLength = Math.max(options.length, sets.length);
    const pool = sets.join("");
    const chars = sets.map((set) => this.random.pick(set));
    while (chars.length < adjustedLength) {
      const next = this.random.pick(pool);
      const last = chars.at(-1);
      if (options.excludeCombos && last && last.toLowerCase() === next.toLowerCase()) continue;
      chars.push(next);
    }
    return { value: this.random.shuffle(chars).join(""), adjustedLength };
  }
}

class WordPasswordGenerator {
  constructor() {
    this.words = window.PSL_WORDS || { en: [], ru: [] };
    this.special = "!@#$%&*?";
    this.random = new SecureRandom();
  }

  makeWord(word, mode) {
    if (mode === "lower") return word.toLowerCase();
    if (mode === "upper") return word.toUpperCase();
    if (mode === "mixed") return [...word].map((char, index) => index % 2 ? char.toLowerCase() : char.toUpperCase()).join("");
    return word[0].toUpperCase() + word.slice(1).toLowerCase();
  }

  generate({ count, separator, digits, special, wordCase = "title", language = "en" }) {
    const dictionary = this.words[language] || this.words.en;
    const parts = Array.from({ length: count }, () => this.makeWord(dictionary[this.random.randomInt(dictionary.length)], wordCase));
    if (digits) parts.splice(this.random.randomInt(parts.length + 1), 0, String(this.random.randomInt(90) + 10));
    let value = parts.join(separator);
    if (special) value += this.special[this.random.randomInt(this.special.length)];
    return {
      value,
      entropy: EntropyCalculator.passphrase(dictionary.length, count, digits, special),
      dictionarySize: dictionary.length
    };
  }
}

class KeyGenerator {
  constructor() {
    this.random = new SecureRandom();
    this.map = {
      A: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      L: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      U: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      D: "0123456789",
      S: "!@#$%^&*"
    };
  }

  generate(template) {
    return [...template].map((token) => this.map[token] ? this.random.pick(this.map[token]) : token).join("");
  }
}

class PwnedChecker {
  async sha1(value) {
    const bytes = new TextEncoder().encode(value);
    const hash = await crypto.subtle.digest("SHA-1", bytes);
    return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  async check(password) {
    const hash = await this.sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { cache: "no-store" });
    if (!response.ok) throw new Error("HIBP недоступен");
    const text = await response.text();
    const row = text.split(/\r?\n/).find((line) => line.startsWith(suffix));
    if (!row) return { status: "checked", found: false, count: 0 };
    return { status: "checked", found: true, count: Number(row.split(":")[1]) || 0 };
  }
}

class ChartVisualizer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.bars = [];
    this.tooltip = document.createElement("div");
    this.tooltip.className = "chart-tooltip";
    document.body.append(this.tooltip);
    this.canvas.addEventListener("mousemove", (event) => this.handleHover(event));
    this.canvas.addEventListener("mouseleave", () => {
      this.tooltip.style.display = "none";
    });
  }

  draw(currentEntropy) {
    const ctx = this.ctx;
    const width = this.canvas.width;
    const height = this.canvas.height;
    const values = [
      { label: "Текущий", entropy: currentEntropy, color: "#2563eb" },
      { label: "Мин. рекоменд.", entropy: 64, color: "#22c55e" },
      { label: "Корпоративный", entropy: 80, color: "#f97316" },
      { label: "Высокий", entropy: 100, color: "#3b82f6" }
    ];
    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--surface").trim();
    ctx.fillRect(0, 0, width, height);
    ctx.strokeStyle = "#94a3b8";
    ctx.beginPath();
    ctx.moveTo(80, 35);
    ctx.lineTo(80, height - 60);
    ctx.lineTo(width - 30, height - 60);
    ctx.stroke();
    const maxEntropy = 110;
    const barWidth = 120;
    const gap = 70;
    this.bars = [];
    values.forEach((item, index) => {
      const barHeight = Math.max(4, (Math.min(item.entropy, maxEntropy) / maxEntropy) * (height - 120));
      const x = 105 + index * (barWidth + gap);
      const y = height - 60 - barHeight;
      this.bars.push({ ...item, x, y, width: barWidth, height: barHeight });
      ctx.fillStyle = item.color;
      ctx.fillRect(x, y, barWidth, barHeight);
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--text").trim();
      ctx.font = "700 18px system-ui";
      ctx.fillText(`${Math.round(item.entropy)} бит`, x + 20, y - 12);
      ctx.font = "600 14px system-ui";
      ctx.fillText(item.label, x, height - 28);
    });
  }

  handleHover(event) {
    const rect = this.canvas.getBoundingClientRect();
    const scaleX = this.canvas.width / rect.width;
    const scaleY = this.canvas.height / rect.height;
    const x = (event.clientX - rect.left) * scaleX;
    const y = (event.clientY - rect.top) * scaleY;
    const hit = this.bars.find((bar) => x >= bar.x && x <= bar.x + bar.width && y >= bar.y && y <= bar.y + bar.height);
    if (!hit) {
      this.tooltip.style.display = "none";
      return;
    }
    this.tooltip.textContent = `${hit.label}: ${Math.round(hit.entropy)} бит практической оценки`;
    this.tooltip.style.left = `${event.clientX + 14}px`;
    this.tooltip.style.top = `${event.clientY + 14}px`;
    this.tooltip.style.display = "block";
  }
}

class App {
  constructor() {
    this.storage = new StorageService();
    this.analyzer = new PasswordAnalyzer();
    this.estimator = new CrackTimeEstimator();
    this.passwordGenerator = new PasswordGenerator();
    this.wordGenerator = new WordPasswordGenerator();
    this.keyGenerator = new KeyGenerator();
    this.pwnedChecker = new PwnedChecker();
    this.chart = new ChartVisualizer(document.querySelector("#crackChart"));
    this.generated = [];
    this.hiddenGenerated = false;
    this.lastBreach = null;
    this.lastAnalysis = null;
    this.presets = {
      "Офисный": { length: 12, upper: true, lower: true, digits: true, special: false },
      "Корпоративный": { length: 16, upper: true, lower: true, digits: true, special: true },
      "Администратор": { length: 24, upper: true, lower: true, digits: true, special: true },
      "Wi-Fi": { length: 20, upper: true, lower: true, digits: true, special: true, excludeAmbiguous: true },
      "Банковский": { length: 32, upper: true, lower: true, digits: true, special: true }
    };
    this.init();
  }

  init() {
    this.bindNavigation();
    this.bindTheme();
    this.bindAnalyzer();
    this.bindGenerators();
    this.bindHistory();
    this.renderPresets();
    this.renderHistory();
    this.updateAnalysis("");
  }

  $(selector) {
    return document.querySelector(selector);
  }

  escape(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  privateMode() {
    return this.$("#privateMode")?.checked ?? true;
  }

  bindNavigation() {
    document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
      document.querySelectorAll(".tab, .section").forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
      this.$(`#${tab.dataset.section}`).classList.add("active");
      this.renderHistory();
    }));
    document.querySelectorAll(".mode-btn").forEach((button) => button.addEventListener("click", () => {
      document.querySelectorAll(".mode-btn, .generator-mode").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      this.$(`#mode-${button.dataset.mode}`).classList.add("active");
    }));
  }

  bindTheme() {
    const saved = localStorage.getItem("psl:theme") || "auto";
    document.documentElement.dataset.theme = saved;
    document.querySelectorAll(".theme-btn").forEach((button) => {
      button.classList.toggle("active", button.dataset.themeChoice === saved);
      button.addEventListener("click", () => {
        document.documentElement.dataset.theme = button.dataset.themeChoice;
        localStorage.setItem("psl:theme", button.dataset.themeChoice);
        document.querySelectorAll(".theme-btn").forEach((item) => item.classList.remove("active"));
        button.classList.add("active");
        this.chart.draw(this.lastAnalysis?.practicalEntropy || 0);
      });
    });
  }

  bindAnalyzer() {
    const input = this.$("#passwordInput");
    input.addEventListener("input", () => {
      this.lastBreach = null;
      this.setPwnedMessage("Проверка утечек выполняется только по кнопке через k-anonymity.", "neutral");
      this.updateAnalysis(input.value);
    });
    this.$("#togglePassword").addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      this.$("#togglePassword").textContent = input.type === "password" ? "Показать" : "Скрыть";
    });
    this.$("#clearAnalyzer").addEventListener("click", () => {
      input.value = "";
      this.lastBreach = null;
      this.updateAnalysis("");
      this.setPwnedMessage("Проверка утечек выполняется только по кнопке через k-anonymity.", "neutral");
    });
    this.$("#checkPwned").addEventListener("click", () => this.checkPwned());
    this.$("#saveCheck").addEventListener("click", () => this.saveCheck());
  }

  bindGenerators() {
    this.$("#passwordLength").addEventListener("input", (event) => {
      this.$("#lengthValue").textContent = event.target.value;
    });
    this.$("#generateRandom").addEventListener("click", () => this.generateRandom());
    this.$("#generatePhrase").addEventListener("click", () => this.generatePhrase());
    this.$("#generateMemorable").addEventListener("click", () => this.generateMemorable());
    this.$("#generateKeys").addEventListener("click", () => this.generateKeys());
    this.$("#generateReadableKeys").addEventListener("click", () => this.generateReadableKeys());
    this.$("#copyAll").addEventListener("click", () => this.copy(this.generated.map((item) => item.value).join("\n")));
    this.$("#hideAll").addEventListener("click", () => {
      this.hiddenGenerated = !this.hiddenGenerated;
      this.$("#hideAll").textContent = this.hiddenGenerated ? "Показать все значения" : "Скрыть все значения";
      this.renderGenerated();
    });
    this.$("#saveTemplate").addEventListener("click", () => this.saveTemplate());
    this.$("#privateMode").addEventListener("change", () => {
      if (this.privateMode()) this.$("#saveGenerated").checked = false;
      this.toast(this.privateMode() ? "Приватный режим включён" : "Приватный режим выключен");
    });
  }

  bindHistory() {
    document.querySelectorAll("[data-export]").forEach((button) => button.addEventListener("click", () => this.exportHistory(button.dataset.export, "txt")));
    document.querySelectorAll("[data-export-csv]").forEach((button) => button.addEventListener("click", () => this.exportHistory(button.dataset.exportCsv, "csv")));
    document.querySelectorAll("[data-clear]").forEach((button) => button.addEventListener("click", () => this.clearList(button.dataset.clear)));
    this.$("#clearAllHistory").addEventListener("click", () => this.clearAllHistory());
  }

  renderPresets() {
    Object.entries(this.presets).forEach(([name, preset]) => {
      const button = document.createElement("button");
      button.className = "preset-btn";
      button.type = "button";
      button.textContent = name;
      button.addEventListener("click", () => this.applyPreset(preset));
      this.$("#presetRow").append(button);
    });
    ["LLLLL-DDDDD", "UUUU-DDDD-UUUU", "AAAAA-AAAAAA-AAAAA"].forEach((template) => this.addTemplateButton(template));
    this.storage.get("templates").forEach((item) => this.addTemplateButton(item.value));
  }

  addTemplateButton(template) {
    const button = document.createElement("button");
    button.className = "preset-btn";
    button.type = "button";
    button.textContent = template;
    button.addEventListener("click", () => {
      this.$("#keyTemplate").value = template;
      this.generateKeys();
    });
    this.$("#templatePresets").append(button);
  }

  applyPreset(preset) {
    this.$("#passwordLength").value = preset.length;
    this.$("#lengthValue").textContent = preset.length;
    this.$("#useUpper").checked = preset.upper;
    this.$("#useLower").checked = preset.lower;
    this.$("#useDigits").checked = preset.digits;
    this.$("#useSpecial").checked = preset.special;
    this.$("#excludeAmbiguous").checked = Boolean(preset.excludeAmbiguous);
    this.generateRandom();
  }

  updateAnalysis(password) {
    const result = this.analyzer.analyze(password, this.lastBreach);
    this.lastAnalysis = result;
    this.renderAnalysis(result);
    this.renderCrackTimes(result.practicalEntropy);
    this.chart.draw(result.practicalEntropy);
  }

  setPwnedMessage(message, type) {
    const node = this.$("#pwnedResult");
    node.className = `status-box ${type}`;
    node.textContent = message;
  }

  async checkPwned() {
    const password = this.$("#passwordInput").value;
    if (!password) {
      this.setPwnedMessage("Введите пароль перед проверкой утечек.", "neutral");
      return;
    }
    this.setPwnedMessage("Проверяем SHA-1 префикс через Have I Been Pwned...", "neutral");
    try {
      this.lastBreach = await this.pwnedChecker.check(password);
      if (this.lastBreach.found) {
        this.setPwnedMessage(`Этот пароль найден в известных утечках. Не используйте его. Встречался: ${this.lastBreach.count.toLocaleString("ru-RU")} раз.`, "danger");
      } else {
        this.setPwnedMessage("Пароль не найден в базе известных утечек. Это не гарантирует абсолютную безопасность.", "ok");
      }
    } catch {
      this.lastBreach = { status: "unavailable", found: false, count: 0 };
      this.setPwnedMessage("Проверка утечек временно недоступна.", "neutral");
    }
    this.updateAnalysis(password);
  }

  saveCheck() {
    if (this.privateMode()) {
      this.toast("В приватном режиме история не сохраняется");
      return;
    }
    if (!this.lastAnalysis?.length) return;
    this.storage.push("checked", {
      length: this.lastAnalysis.length,
      level: this.lastAnalysis.level.name,
      theoreticalEntropy: this.lastAnalysis.theoreticalEntropy,
      practicalEntropy: this.lastAnalysis.practicalEntropy,
      verdict: this.lastAnalysis.verdict,
      breach: this.lastBreach?.status || "not_checked"
    });
    this.toast("Сохранены только технические данные проверки");
    this.renderHistory();
  }

  renderAnalysis(result) {
    const fill = this.$("#strengthFill");
    fill.style.width = `${result.level.score}%`;
    fill.style.background = result.level.color;
    this.$("#strengthLabel").textContent = result.length ? `${result.verdict}: ${result.keyRecommendation}` : "Введите пароль для анализа";
    const breachText = this.lastBreach?.found ? `найден, ${this.lastBreach.count.toLocaleString("ru-RU")} раз` : this.lastBreach?.status === "checked" ? "не найден" : "не проверялся";
    const summary = [
      ["Вердикт", result.verdict],
      ["Теоретическая энтропия", `${result.theoreticalEntropy.toFixed(1)} бит`],
      ["Практическая оценка", `${result.practicalEntropy.toFixed(1)} бит`],
      ["Проверка утечек", breachText],
      ["Ключевая рекомендация", result.keyRecommendation, "wide"]
    ];
    this.$("#summaryCards").innerHTML = summary.map(([label, value, wide]) => `<div class="metric-card ${wide || ""}"><div class="metric-label">${this.escape(label)}</div><div class="metric-value">${this.escape(value)}</div></div>`).join("");
    const cards = [
      ["Длина", result.length],
      ["Уровень", result.level.name],
      ["Повторы", result.hasRepeats ? "найдены" : "нет"],
      ["Шаблоны", result.weakMatches.length ? result.weakMatches.join(", ") : "нет"],
      ["Словарь/транслит", result.dictionaryMatches.length ? result.dictionaryMatches.join(", ") : "нет"],
      ["Даты и годы", result.dateMatches.length ? result.dateMatches.join(", ") : "нет"]
    ];
    this.$("#analysisCards").innerHTML = cards.map(([label, value]) => `<div class="metric-card"><div class="metric-label">${this.escape(label)}</div><div class="metric-value">${this.escape(value)}</div></div>`).join("");
    const flags = [["Заглавные", result.flags.upper, true], ["Строчные", result.flags.lower, true], ["Цифры", result.flags.digits, true], ["Спецсимволы", result.flags.special, true], ["Последовательности", result.sequenceMatches.length > 0, false]];
    this.$("#charsetBadges").innerHTML = flags.map(([label, value, positive]) => {
      const good = positive ? value : !value;
      return `<span class="badge ${good ? "ok" : "bad"}">${this.escape(label)}: ${value ? "да" : "нет"}</span>`;
    }).join("");
    this.$("#recommendations").innerHTML = result.recommendations.map((tip) => `<div class="recommendation">${this.escape(tip)}</div>`).join("");
  }

  renderCrackTimes(entropy) {
    this.$("#crackTimes").innerHTML = this.estimator.forEntropy(entropy).map((item) => `
      <div class="time-item">
        <div class="time-label">${this.escape(item.label)}<br>${item.guesses.toLocaleString("ru-RU")} попыток/сек</div>
        <div class="time-value">${this.escape(item.formatted)}</div>
      </div>`).join("");
  }

  generatorOptions() {
    return {
      length: Number(this.$("#passwordLength").value),
      upper: this.$("#useUpper").checked,
      lower: this.$("#useLower").checked,
      digits: this.$("#useDigits").checked,
      special: this.$("#useSpecial").checked,
      excludeSimilar: this.$("#excludeSimilar").checked,
      excludeAmbiguous: this.$("#excludeAmbiguous").checked,
      excludeCombos: this.$("#excludeCombos").checked
    };
  }

  generateRandom() {
    const options = this.generatorOptions();
    const count = Number(this.$("#passwordCount").value);
    const result = Array.from({ length: count }, () => this.passwordGenerator.generate(options));
    const adjusted = result.some((item) => item.adjustedLength !== options.length);
    this.$("#generatorWarning").textContent = adjusted ? "Длина была автоматически увеличена, чтобы вместить все выбранные наборы символов." : "";
    this.showGenerated(result.map((item) => ({ value: item.value, entropy: EntropyCalculator.theoretical(item.value) })), "random", { length: options.length, count });
  }

  generatePhrase() {
    const options = {
      language: this.$("#phraseLanguage").value,
      count: Number(this.$("#phraseWordCount").value),
      separator: this.$("#phraseSeparator").value,
      digits: this.$("#phraseDigits").checked,
      special: this.$("#phraseSpecial").checked
    };
    const count = Number(this.$("#phraseCount").value);
    this.showGenerated(Array.from({ length: count }, () => this.wordGenerator.generate(options)), "phrase", { ...options, generatedCount: count });
  }

  generateMemorable() {
    const options = {
      count: Number(this.$("#wordCount").value),
      separator: this.$("#wordSeparator").value,
      digits: this.$("#wordDigits").checked,
      special: this.$("#wordSpecial").checked,
      wordCase: this.$("#wordCase").value,
      language: "en"
    };
    const count = Number(this.$("#memorableCount").value);
    this.showGenerated(Array.from({ length: count }, () => this.wordGenerator.generate(options)), "memorable", { ...options, generatedCount: count });
  }

  generateKeys() {
    const template = this.$("#keyTemplate").value || "AAAAA-AAAAAA-AAAAA";
    const count = Number(this.$("#keyCount").value);
    this.showGenerated(Array.from({ length: count }, () => {
      const value = this.keyGenerator.generate(template);
      return { value, entropy: EntropyCalculator.theoretical(value) };
    }), "key", { template, count });
  }

  generateReadableKeys() {
    const count = Number(this.$("#readableCount").value);
    const wordCount = Number(this.$("#readableWordCount").value);
    const separator = this.$("#readableSeparator").value;
    const digits = this.$("#readableDigits").checked;
    const wordCase = this.$("#readableMixed").checked ? "mixed" : "title";
    this.showGenerated(Array.from({ length: count }, () => this.wordGenerator.generate({ count: wordCount, separator, digits, special: false, wordCase, language: "en" })), "readable-key", { wordCount, separator, digits, count });
  }

  showGenerated(items, type, params) {
    clearTimeout(this.autoClearTimer);
    this.hiddenGenerated = false;
    this.$("#hideAll").textContent = "Скрыть все значения";
    this.generated = items.filter((item) => item.value).map((item) => ({ ...item, type }));
    this.renderGenerated();
    this.storeGeneration(type, params);
    if (this.$("#autoClear").checked) {
      this.autoClearTimer = setTimeout(() => {
        this.generated = [];
        this.renderGenerated();
        this.toast("Сгенерированные значения автоматически очищены");
      }, 60000);
    }
  }

  storeGeneration(type, params) {
    if (this.privateMode()) return;
    const saveValues = this.$("#saveGenerated").checked;
    this.storage.push("generated", {
      type,
      count: this.generated.length,
      params,
      values: saveValues ? this.generated.map((item) => item.value) : [],
      savedValues: saveValues
    });
    this.renderHistory();
  }

  renderGenerated() {
    this.$("#generatedList").innerHTML = this.generated.length ? this.generated.map((item, index) => `
      <div class="generated-item">
        <div>
          <div class="generated-value ${this.hiddenGenerated ? "hidden" : ""}">${this.hiddenGenerated ? "••••••••••" : this.escape(item.value)}</div>
          <div class="generated-meta">${this.escape(item.type)} · ${Number(item.entropy).toFixed(1)} бит оценки</div>
        </div>
        <div class="generated-actions">
          <button class="icon-btn" data-copy-index="${index}" type="button" title="Копировать">⧉</button>
          <button class="icon-btn" data-copy-clear-index="${index}" type="button" title="Скопировать и очистить">⧉×</button>
          <button class="icon-btn" data-fav-index="${index}" type="button" title="В избранное">☆</button>
        </div>
      </div>`).join("") : `<div class="history-item">Сгенерированные значения очищены или ещё не созданы.</div>`;
    document.querySelectorAll("[data-copy-index]").forEach((button) => button.addEventListener("click", () => this.copy(this.generated[button.dataset.copyIndex].value)));
    document.querySelectorAll("[data-copy-clear-index]").forEach((button) => button.addEventListener("click", () => this.copyAndClear(Number(button.dataset.copyClearIndex))));
    document.querySelectorAll("[data-fav-index]").forEach((button) => button.addEventListener("click", () => this.addFavorite(Number(button.dataset.favIndex))));
  }

  async copyAndClear(index) {
    await this.copy(this.generated[index].value);
    this.generated.splice(index, 1);
    this.renderGenerated();
  }

  addFavorite(index) {
    if (this.privateMode()) {
      this.toast("В приватном режиме избранное не сохраняется");
      return;
    }
    if (!confirm("Значение будет сохранено в браузере в LocalStorage. Продолжить?")) return;
    this.storage.push("favorites", { value: this.generated[index].value, type: this.generated[index].type });
    this.toast("Добавлено в избранное");
    this.renderHistory();
  }

  saveTemplate() {
    const value = this.$("#keyTemplate").value.trim();
    if (!value) return;
    if (this.privateMode()) {
      this.toast("В приватном режиме шаблоны не сохраняются");
      return;
    }
    const templates = this.storage.get("templates");
    if (!templates.some((item) => item.value === value)) {
      this.storage.set("templates", [{ value, createdAt: new Date().toISOString() }, ...templates].slice(0, 50));
      this.addTemplateButton(value);
      this.renderHistory();
      this.toast("Шаблон сохранён");
    }
  }

  renderHistory() {
    this.renderGeneratedHistory();
    this.renderCheckedHistory();
    this.renderSimpleList("#favoritesList", this.storage.get("favorites"), "Избранное пусто");
    this.renderSimpleList("#templatesList", this.storage.get("templates"), "Шаблонов пока нет");
  }

  renderGeneratedHistory() {
    const list = this.storage.get("generated");
    this.$("#generatedHistory").innerHTML = list.length ? list.map((item) => `
      <div class="history-item">
        <div class="history-value">${item.savedValues ? this.escape(item.values.join(", ")) : "Значения не сохранены"}</div>
        <div class="generated-meta">${this.escape(item.type)} · ${item.count} шт. · ${new Date(item.createdAt).toLocaleString("ru-RU")}</div>
      </div>`).join("") : `<div class="history-item">История генераций пуста</div>`;
  }

  renderCheckedHistory() {
    const list = this.storage.get("checked");
    this.$("#checkedHistory").innerHTML = list.length ? list.map((item) => `
      <div class="history-item">
        <div class="history-value">Длина: ${item.length} · ${this.escape(item.verdict)}</div>
        <div class="generated-meta">${this.escape(item.level)} · теория ${Number(item.theoreticalEntropy).toFixed(1)} бит · практика ${Number(item.practicalEntropy).toFixed(1)} бит · ${new Date(item.createdAt).toLocaleString("ru-RU")}</div>
      </div>`).join("") : `<div class="history-item">История проверок пуста</div>`;
  }

  renderSimpleList(selector, list, emptyText) {
    this.$(selector).innerHTML = list.length ? list.map((item) => `
      <div class="history-item">
        <div class="history-value">${this.escape(item.value)}</div>
        <div class="generated-meta">${this.escape(item.type || "template")} · ${new Date(item.createdAt).toLocaleString("ru-RU")}</div>
      </div>`).join("") : `<div class="history-item">${emptyText}</div>`;
  }

  clearList(name) {
    if (!confirm("Удалить выбранные локальные данные?")) return;
    this.storage.clear(name);
    this.renderHistory();
    this.toast("Данные очищены");
  }

  clearAllHistory() {
    if (!confirm("Очистить все данные Password Security Lab из LocalStorage?")) return;
    this.storage.clearAllProjectData();
    this.renderHistory();
    this.toast("Вся история очищена");
  }

  exportHistory(name, format) {
    if (!confirm("Экспорт может содержать чувствительные данные. Сохраняйте файл только в безопасном месте.")) return;
    const data = this.storage.get(name);
    const content = format === "csv"
      ? this.toCsv(data)
      : data.map((item) => JSON.stringify(item, null, 0)).join("\n");
    const blob = new Blob([content], { type: format === "csv" ? "text/csv" : "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `password-security-lab-${name}.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  toCsv(data) {
    const keys = [...new Set(data.flatMap((item) => Object.keys(item)))];
    return [keys.join(","), ...data.map((item) => keys.map((key) => `"${String(item[key] ?? "").replaceAll('"', '""')}"`).join(","))].join("\n");
  }

  async copy(value) {
    if (!value) return;
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    this.toast("Скопировано");
  }

  toast(message) {
    const toast = this.$("#toast");
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => toast.classList.remove("show"), 1800);
  }
}

document.addEventListener("DOMContentLoaded", () => new App());
