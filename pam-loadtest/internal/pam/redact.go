package pam

import (
	"regexp"
	"strings"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password\s*[=:]\s*)[^\s,;]+`),
	regexp.MustCompile(`(?i)(cookie\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)(x-auth-token\s*[=:]\s*)[^\s,;]+`),
	regexp.MustCompile(`(?i)(authorization\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
}

var queryTokenStart = regexp.MustCompile(`(?i)(?:^|[?&]|\\u0026|%26)token=`)
var sensitivePathSegment = regexp.MustCompile(`(?i)(/(?:webpam/)?sessions|/db-sessions|/assets|/accounts)/[^/?#]+`)

func Redact(value string) string {
	out := redactQueryTokens(value)
	for i, re := range sensitivePatterns {
		if i == len(sensitivePatterns)-1 {
			out = re.ReplaceAllString(out, "{uuid}")
		} else {
			out = re.ReplaceAllString(out, `${1}[REDACTED]`)
		}
	}
	return out
}

func RedactPath(value string) string {
	return Redact(sensitivePathSegment.ReplaceAllString(value, `${1}/{id}`))
}

func redactQueryTokens(value string) string {
	var out strings.Builder
	cursor := 0
	for cursor < len(value) {
		match := queryTokenStart.FindStringIndex(value[cursor:])
		if match == nil {
			out.WriteString(value[cursor:])
			break
		}
		start, valueStart := cursor+match[0], cursor+match[1]
		out.WriteString(value[cursor:valueStart])
		out.WriteString("[REDACTED]")
		cursor = queryTokenValueEnd(value, valueStart)
		if cursor == start {
			cursor++
		}
	}
	return out.String()
}

func queryTokenValueEnd(value string, start int) int {
	for index := start; index < len(value); index++ {
		suffix := value[index:]
		if value[index] == '&' || value[index] == '#' || value[index] == '"' || value[index] == '\'' || strings.HasPrefix(strings.ToLower(suffix), `\u0026`) || strings.HasPrefix(strings.ToLower(suffix), "%26") {
			return index
		}
	}
	return len(value)
}
