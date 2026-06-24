"use strict";

// StorageService centralizes all LocalStorage operations and keeps each list capped.
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

  toggleFavorite(value) {
    const favorites = this.get("favorites");
    const exists = favorites.some((item) => item.value === value);
    const next = exists
      ? favorites.filter((item) => item.value !== value)
      : [{ value, createdAt: new Date().toISOString() }, ...favorites].slice(0, 50);
    this.set("favorites", next);
    return !exists;
  }
}

// EntropyCalculator estimates the search space and applies penalties for obvious weaknesses.
class EntropyCalculator {
  static charsets = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    digits: "0123456789",
    special: "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
  };

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
    if (flags.upper) size += 26;
    if (flags.lower) size += 26;
    if (flags.digits) size += 10;
    if (flags.special) size += 32;
    return Math.max(size, 1);
  }

  static calculate(password) {
    if (!password) return 0;
    const flags = this.detect(password);
    const rawEntropy = password.length * Math.log2(this.poolSize(flags));
    const repeatPenalty = /(.)\1{2,}/.test(password) ? 10 : 0;
    const sequencePenalty = PasswordAnalyzer.sequencePatterns.some((pattern) => password.toLowerCase().includes(pattern)) ? 12 : 0;
    const dictionaryPenalty = PasswordAnalyzer.dictionary.some((word) => password.toLowerCase().includes(word)) ? 14 : 0;
    return Math.max(0, rawEntropy - repeatPenalty - sequencePenalty - dictionaryPenalty);
  }
}

// CrackTimeEstimator converts entropy into rough brute-force time for several attacker profiles.
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
    const units = [
      ["секунд", 60],
      ["минут", 60],
      ["часов", 24],
      ["дней", 30],
      ["месяцев", 12],
      ["лет", 1000],
      ["тысяч лет", 1000],
      ["миллионов лет", 1000],
      ["миллиардов лет", Infinity]
    ];
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

// PasswordAnalyzer combines entropy, pattern checks, dictionary hits, and recommendations.
class PasswordAnalyzer {
  static weakPatterns = ["123456", "qwerty", "password", "admin", "welcome", "letmein", "qwerty123", "password123", "admin123"];
  static sequencePatterns = ["abcdef", "qwerty", "123456", "654321", "aaa111"];
  static dictionary = ["password", "admin", "welcome", "login", "user", "dragon", "monkey", "master", "football", "iloveyou", "secret"];

  analyze(password) {
    const flags = EntropyCalculator.detect(password);
    const entropy = EntropyCalculator.calculate(password);
    const lower = password.toLowerCase();
    const weakMatches = PasswordAnalyzer.weakPatterns.filter((pattern) => lower.includes(pattern));
    const sequenceMatches = PasswordAnalyzer.sequencePatterns.filter((pattern) => lower.includes(pattern));
    const hasRepeats = /(.)\1{2,}/.test(password) || /(.{2,})\1{1,}/.test(password);
    const dictionaryMatches = PasswordAnalyzer.dictionary.filter((word) => lower.includes(word));
    const level = this.level(entropy, password.length, weakMatches.length + sequenceMatches.length + dictionaryMatches.length + (hasRepeats ? 1 : 0));
    return {
      password,
      length: password.length,
      entropy,
      level,
      flags,
      weakMatches,
      sequenceMatches,
      hasRepeats,
      dictionaryMatches,
      quality: this.qualityText(level.name),
      recommendations: this.recommendations(password, flags, weakMatches, sequenceMatches, hasRepeats, dictionaryMatches)
    };
  }

  level(entropy, length, penalties) {
    let score = Math.min(100, Math.round(entropy * 1.25 + Math.min(length, 32)));
    score -= penalties * 15;
    score = Math.max(0, score);
    if (score < 25) return { name: "Очень слабый", score, color: "var(--danger)" };
    if (score < 45) return { name: "Слабый", score, color: "var(--orange)" };
    if (score < 65) return { name: "Средний", score, color: "var(--yellow)" };
    if (score < 85) return { name: "Хороший", score, color: "var(--green)" };
    return { name: "Отличный", score, color: "var(--blue)" };
  }

  qualityText(level) {
    const map = {
      "Очень слабый": "Пароль легко угадывается и не подходит для реальных аккаунтов.",
      "Слабый": "Есть базовая защита, но пароль всё ещё рискованный.",
      "Средний": "Приемлемо для низкого риска, но лучше усилить.",
      "Хороший": "Хорошая стойкость для большинства бытовых сценариев.",
      "Отличный": "Высокая стойкость и здоровый запас энтропии."
    };
    return map[level];
  }

  recommendations(password, flags, weak, sequences, repeats, dictionary) {
    const tips = [];
    if (password.length < 12) tips.push("Увеличьте длину хотя бы до 12-16 символов.");
    if (!flags.upper) tips.push("Добавьте заглавные буквы.");
    if (!flags.lower) tips.push("Добавьте строчные буквы.");
    if (!flags.digits) tips.push("Добавьте цифры.");
    if (!flags.special) tips.push("Добавьте специальные символы.");
    if (weak.length) tips.push(`Замените слабые шаблоны: ${weak.join(", ")}.`);
    if (sequences.length) tips.push(`Избегайте последовательностей: ${sequences.join(", ")}.`);
    if (repeats) tips.push("Уберите повторяющиеся символы или блоки.");
    if (dictionary.length) tips.push(`Не используйте словарные слова: ${dictionary.join(", ")}.`);
    if (!tips.length) tips.push("Пароль выглядит устойчивым. Для критичных сервисов используйте уникальный пароль.");
    return tips;
  }
}

// PasswordGenerator uses Web Crypto randomness and configurable character pools.
class PasswordGenerator {
  constructor() {
    this.upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    this.lower = "abcdefghijkmnopqrstuvwxyz";
    this.digits = "23456789";
    this.special = "!@#$%^&*_-+=?";
    this.similar = "Il1O0";
    this.ambiguous = "{}[]()/\\'\"`~,;:.<>";
  }

  randomInt(max) {
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % max;
  }

  pick(chars) {
    return chars[this.randomInt(chars.length)];
  }

  clean(chars, options) {
    let value = chars;
    if (options.excludeSimilar) value = [...value].filter((char) => !this.similar.includes(char)).join("");
    if (options.excludeAmbiguous) value = [...value].filter((char) => !this.ambiguous.includes(char)).join("");
    return value;
  }

  generate(options) {
    const sets = [];
    if (options.upper) sets.push(this.clean(this.upper, options));
    if (options.lower) sets.push(this.clean(this.lower, options));
    if (options.digits) sets.push(this.clean(this.digits, options));
    if (options.special) sets.push(this.clean(this.special, options));
    const pool = sets.join("");
    if (!pool) return "";
    const chars = sets.map((set) => this.pick(set));
    while (chars.length < options.length) {
      const next = this.pick(pool);
      const last = chars.at(-1);
      if (options.excludeCombos && last && last.toLowerCase() === next.toLowerCase()) continue;
      chars.push(next);
    }
    return this.shuffle(chars).join("");
  }

  shuffle(chars) {
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = this.randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars;
  }
}

// WordPasswordGenerator creates readable passphrases and human-friendly key fragments.
class WordPasswordGenerator {
  constructor() {
    this.words = ["Forest", "Tiger", "Rocket", "Blue", "Horse", "River", "Moon", "Cloud", "Fox", "Delta", "Storm", "Cedar", "Nova", "Pixel", "Atlas", "Signal", "Quartz", "Falcon", "Meadow", "Vector", "Silver", "Orbit", "Amber", "Harbor", "Zenith", "Comet", "Prairie", "Summit"];
    this.special = "!@#$%&*?";
    this.passwordGenerator = new PasswordGenerator();
  }

  makeWord(word, mode) {
    if (mode === "lower") return word.toLowerCase();
    if (mode === "upper") return word.toUpperCase();
    if (mode === "mixed") return [...word].map((char, index) => index % 2 ? char.toLowerCase() : char.toUpperCase()).join("");
    return word[0].toUpperCase() + word.slice(1).toLowerCase();
  }

  generate({ count, separator, digits, special, wordCase }) {
    const parts = Array.from({ length: count }, () => {
      const word = this.words[this.passwordGenerator.randomInt(this.words.length)];
      return this.makeWord(word, wordCase);
    });
    if (digits) parts.splice(this.passwordGenerator.randomInt(parts.length + 1), 0, String(this.passwordGenerator.randomInt(90) + 10));
    let value = parts.join(separator);
    if (special) value += this.special[this.passwordGenerator.randomInt(this.special.length)];
    return value;
  }
}

// KeyGenerator replaces template tokens with random characters while preserving separators.
class KeyGenerator {
  constructor() {
    this.generator = new PasswordGenerator();
    this.map = {
      A: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      L: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      U: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      D: "0123456789",
      S: "!@#$%^&*"
    };
  }

  generate(template) {
    return [...template].map((token) => this.map[token] ? this.generator.pick(this.map[token]) : token).join("");
  }
}

// ChartVisualizer draws a dependency-free interactive canvas chart.
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
    ctx.lineWidth = 1;
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
      const barHeight = Math.max(4, ((Math.min(item.entropy, maxEntropy) / maxEntropy) * (height - 120)));
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
    this.tooltip.textContent = `${hit.label}: ${Math.round(hit.entropy)} бит энтропии`;
    this.tooltip.style.left = `${event.clientX + 14}px`;
    this.tooltip.style.top = `${event.clientY + 14}px`;
    this.tooltip.style.display = "block";
  }
}

// App wires UI events to independent modules and keeps rendering concerns in one place.
class App {
  constructor() {
    this.storage = new StorageService();
    this.analyzer = new PasswordAnalyzer();
    this.estimator = new CrackTimeEstimator();
    this.passwordGenerator = new PasswordGenerator();
    this.wordGenerator = new WordPasswordGenerator();
    this.keyGenerator = new KeyGenerator();
    this.chart = new ChartVisualizer(document.querySelector("#crackChart"));
    this.generated = [];
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
    this.renderPresets();
    this.renderHistory();
    this.generateRandom();
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
        this.chart.draw(this.lastEntropy || 0);
      });
    });
  }

  bindAnalyzer() {
    const input = this.$("#passwordInput");
    input.addEventListener("input", () => this.updateAnalysis(input.value));
    this.$("#togglePassword").addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
      this.$("#togglePassword").textContent = input.type === "password" ? "Показать" : "Скрыть";
    });
    this.$("#clearAnalyzer").addEventListener("click", () => {
      input.value = "";
      this.updateAnalysis("");
    });
  }

  bindGenerators() {
    this.$("#passwordLength").addEventListener("input", (event) => {
      this.$("#lengthValue").textContent = event.target.value;
    });
    this.$("#generateRandom").addEventListener("click", () => this.generateRandom());
    this.$("#generateMemorable").addEventListener("click", () => this.generateMemorable());
    this.$("#generateKeys").addEventListener("click", () => this.generateKeys());
    this.$("#generateReadableKeys").addEventListener("click", () => this.generateReadableKeys());
    this.$("#copyAll").addEventListener("click", () => this.copy(this.generated.map((item) => item.value).join("\n")));
    this.$("#saveTemplate").addEventListener("click", () => this.saveTemplate());
    document.querySelectorAll("[data-export]").forEach((button) => button.addEventListener("click", () => this.exportHistory(button.dataset.export, "txt")));
    document.querySelectorAll("[data-export-csv]").forEach((button) => button.addEventListener("click", () => this.exportHistory(button.dataset.exportCsv, "csv")));
  }

  renderPresets() {
    const row = this.$("#presetRow");
    Object.entries(this.presets).forEach(([name, preset]) => {
      const button = document.createElement("button");
      button.className = "preset-btn";
      button.type = "button";
      button.textContent = name;
      button.addEventListener("click", () => this.applyPreset(preset));
      row.append(button);
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
    const result = this.analyzer.analyze(password);
    this.lastEntropy = result.entropy;
    if (password) {
      this.storage.push("checked", { value: password, entropy: result.entropy, level: result.level.name });
    }
    this.renderAnalysis(result);
    this.renderCrackTimes(result.entropy);
    this.chart.draw(result.entropy);
  }

  renderAnalysis(result) {
    const fill = this.$("#strengthFill");
    fill.style.width = `${result.level.score}%`;
    fill.style.background = result.level.color;
    this.$("#strengthLabel").textContent = result.password ? `${result.level.name}: ${result.quality}` : "Введите пароль для анализа";
    const cards = [
      ["Длина", result.length],
      ["Энтропия", `${result.entropy.toFixed(1)} бит`],
      ["Уровень", result.level.name],
      ["Повторы", result.hasRepeats ? "найдены" : "нет"],
      ["Шаблоны", result.weakMatches.length ? result.weakMatches.join(", ") : "нет"],
      ["Словарь", result.dictionaryMatches.length ? result.dictionaryMatches.join(", ") : "нет"]
    ];
    this.$("#analysisCards").innerHTML = cards.map(([label, value]) => `<div class="metric-card"><div class="metric-label">${this.escape(label)}</div><div class="metric-value">${this.escape(value)}</div></div>`).join("");
    const flags = [
      ["Заглавные", result.flags.upper, true],
      ["Строчные", result.flags.lower, true],
      ["Цифры", result.flags.digits, true],
      ["Спецсимволы", result.flags.special, true],
      ["Последовательности", result.sequenceMatches.length > 0, false]
    ];
    this.$("#charsetBadges").innerHTML = flags.map(([label, value, positive]) => {
      const good = positive ? value : !value;
      return `<span class="badge ${good ? "ok" : "bad"}">${this.escape(label)}: ${value ? "да" : "нет"}</span>`;
    }).join("");
    this.$("#recommendations").innerHTML = result.recommendations.map((tip) => `<div class="recommendation">${this.escape(tip)}</div>`).join("");
  }

  renderCrackTimes(entropy) {
    this.$("#crackTimes").innerHTML = this.estimator.forEntropy(entropy).map((item) => `
      <div class="time-item">
        <div class="time-label">${item.label}<br>${item.guesses.toLocaleString("ru-RU")} попыток/сек</div>
        <div class="time-value">${item.formatted}</div>
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
    this.showGenerated(Array.from({ length: count }, () => this.passwordGenerator.generate(options)), "random");
  }

  generateMemorable() {
    const options = {
      count: Number(this.$("#wordCount").value),
      separator: this.$("#wordSeparator").value,
      digits: this.$("#wordDigits").checked,
      special: this.$("#wordSpecial").checked,
      wordCase: this.$("#wordCase").value
    };
    const count = Number(this.$("#memorableCount").value);
    this.showGenerated(Array.from({ length: count }, () => this.wordGenerator.generate(options)), "memorable");
  }

  generateKeys() {
    const template = this.$("#keyTemplate").value || "AAAAA-AAAAAA-AAAAA";
    const count = Number(this.$("#keyCount").value);
    this.showGenerated(Array.from({ length: count }, () => this.keyGenerator.generate(template)), "key");
  }

  generateReadableKeys() {
    const count = Number(this.$("#readableCount").value);
    const wordCount = Number(this.$("#readableWordCount").value);
    const separator = this.$("#readableSeparator").value;
    const digits = this.$("#readableDigits").checked;
    const wordCase = this.$("#readableMixed").checked ? "mixed" : "title";
    this.showGenerated(Array.from({ length: count }, () => this.wordGenerator.generate({ count: wordCount, separator, digits, special: false, wordCase })), "readable-key");
  }

  showGenerated(values, type) {
    this.generated = values.filter(Boolean).map((value) => ({ value, type, entropy: EntropyCalculator.calculate(value) }));
    this.generated.forEach((item) => this.storage.push("generated", item));
    this.$("#generatedList").innerHTML = this.generated.map((item, index) => `
      <div class="generated-item">
        <div>
          <div class="generated-value">${this.escape(item.value)}</div>
          <div class="generated-meta">${item.type} · ${item.entropy.toFixed(1)} бит энтропии</div>
        </div>
        <div class="generated-actions">
          <button class="icon-btn" data-copy-index="${index}" type="button" title="Копировать">⧉</button>
          <button class="icon-btn" data-fav-index="${index}" type="button" title="В избранное">☆</button>
        </div>
      </div>`).join("");
    document.querySelectorAll("[data-copy-index]").forEach((button) => button.addEventListener("click", () => this.copy(this.generated[button.dataset.copyIndex].value)));
    document.querySelectorAll("[data-fav-index]").forEach((button) => button.addEventListener("click", () => {
      const added = this.storage.toggleFavorite(this.generated[button.dataset.favIndex].value);
      this.toast(added ? "Добавлено в избранное" : "Удалено из избранного");
      this.renderHistory();
    }));
    this.renderHistory();
  }

  saveTemplate() {
    const value = this.$("#keyTemplate").value.trim();
    if (!value) return;
    const templates = this.storage.get("templates");
    if (!templates.some((item) => item.value === value)) {
      this.storage.set("templates", [{ value, createdAt: new Date().toISOString() }, ...templates].slice(0, 50));
      this.addTemplateButton(value);
      this.renderHistory();
      this.toast("Шаблон сохранён");
    }
  }

  renderHistory() {
    this.renderList("#generatedHistory", this.storage.get("generated"));
    this.renderList("#checkedHistory", this.storage.get("checked"));
    this.renderList("#favoritesList", this.storage.get("favorites"));
    this.renderList("#templatesList", this.storage.get("templates"));
  }

  renderList(selector, list) {
    const node = this.$(selector);
    if (!node) return;
    node.innerHTML = list.length ? list.map((item) => `
      <div class="history-item">
        <div class="history-value">${this.escape(item.value)}</div>
        <div class="generated-meta">${this.escape(item.level || item.type || "template")} ${item.entropy ? `· ${Number(item.entropy).toFixed(1)} бит` : ""} · ${new Date(item.createdAt).toLocaleString("ru-RU")}</div>
      </div>`).join("") : `<div class="history-item">Пока пусто</div>`;
  }

  exportHistory(name, format) {
    const data = this.storage.get(name);
    const content = format === "csv"
      ? ["value,type,level,entropy,createdAt", ...data.map((item) => [item.value, item.type || "", item.level || "", item.entropy || "", item.createdAt].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))].join("\n")
      : data.map((item) => `${item.value} | ${item.type || item.level || ""} | ${item.entropy || ""} | ${item.createdAt}`).join("\n");
    const blob = new Blob([content], { type: format === "csv" ? "text/csv" : "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `password-security-lab-${name}.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
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
