package report

import (
	"os"
	"strings"
)

var translations = map[string]map[string]string{
	"ru": {
		"IP quality":                         "Качество IP",
		"Region & services":                  "Регион и сервисы",
		"Reputation lists & mail":            "Чёрные списки и почта",
		"Censorship":                         "Цензура",
		"Routes":                             "Маршруты",
		"Runs analysed:":                     "Разобрано запусков:",
		"Every check answered in every run.": "Все проверки ответили во всех запусках.",
		"Checks that did not always answer (answered / runs; ? no answer, ! error):": "Проверки, которые отвечали не всегда (ответили / запусков; ? нет ответа, ! ошибка):",
		"analysis":                          "выводы",
		"method":                            "метод",
		"fastest":                           "быстрейший",
		"Benchmark":                         "Бенчмарк",
		"Lookup":                            "Поиск",
		"Address":                           "Адрес",
		"Via":                               "Через",
		"Also seen":                         "Ещё видно",
		"Place":                             "Место",
		"Route":                             "Маршрут",
		"Registry":                          "Реестр",
		"geo-consistent":                    "совпадает с геолокацией",
		"geo-discrepant":                    "не совпадает с геолокацией",
		"Type":                              "Тип",
		"Score":                             "Оценка",
		"Factors":                           "Факторы",
		"usage":                             "адрес",
		"company":                           "компания",
		"very low":                          "очень низкая",
		"low":                               "низкая",
		"medium":                            "средняя",
		"high":                              "высокая",
		"very high":                         "очень высокая",
		"clean":                             "чисто",
		"detected":                          "обнаружено",
		"not reported":                      "нет данных",
		"waiting":                           "ожидание",
		"unavailable":                       "недоступно",
		"not on local interfaces (offline)": "нет на локальных интерфейсах (offline)",
		"no local data for this address; run `cii data update`": "нет локальных данных об адресе; запустите `cii data update`",
		"Region":                              "Регион",
		"platforms":                           "платформы",
		"says":                                "считает",
		"= CDN edge":                          "= узел CDN",
		"marks":                               "отметки",
		"yes":                                 "да",
		"no":                                  "нет",
		"partial":                             "частично",
		"blocked":                             "заблокировано",
		"unknown":                             "неизвестно",
		"error":                               "ошибка",
		"more in --debug and the log":         "ещё в --debug и логе",
		"checking":                            "проверки",
		"detecting the public address":        "определяю публичный адрес",
		"benchmark":                           "бенчмарк",
		"Ctrl+C stops and shows what is done": "Ctrl+C остановит и покажет готовое",
		"more lines, the full view is printed when the run ends": "строк ещё, полный вид — после окончания",
		"host contacted":      "хост в журнале",
		"hosts contacted":     "хостов в журнале",
		"no network contacts": "сетевых обращений не было",
		"checks failed":       "проверок с ошибкой",
		"--extended check":    "проверка --extended",
		"details":             "подробности",
		"log not written":     "лог не записан",
	},
}

func Translate(lang, s string) string {
	if v, ok := translations[lang][s]; ok {
		return v
	}
	return s
}

func (m marks) tr(s string) string { return Translate(m.lang, s) }

func DetectLang() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ru") {
				return "ru"
			}
			return "en"
		}
	}
	return "en"
}
