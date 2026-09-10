package reports

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

func writePDF(path string, lines []string) error {
	lines = wrap(lines, 88)
	const linesPerPage = 46
	if len(lines) == 0 {
		lines = []string{"InfraSeal Report"}
	}
	pageCount := (len(lines) + linesPerPage - 1) / linesPerPage
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", ""}
	kids := make([]string, 0, pageCount)
	for page := 0; page < pageCount; page++ {
		pageID := 3 + page*2
		contentID := pageID + 1
		kids = append(kids, fmt.Sprintf("%d 0 R", pageID))
		chunk := lines[page*linesPerPage:]
		if len(chunk) > linesPerPage {
			chunk = chunk[:linesPerPage]
		}
		content := pdfContent(chunk, page+1, pageCount)
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", 3+pageCount*2, contentID))
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content))
	}
	objects[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pageCount)
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func pdfContent(lines []string, page, pages int) string {
	var b strings.Builder
	b.WriteString("BT\n/F1 10 Tf\n14 TL\n48 748 Td\n")
	for _, line := range lines {
		fmt.Fprintf(&b, "(%s) Tj\nT*\n", escapePDF(line))
	}
	fmt.Fprintf(&b, "T*\n(Page %d of %d) Tj\nET", page, pages)
	return b.String()
}

func wrap(lines []string, width int) []string {
	var out []string
	for _, line := range lines {
		if len(line) <= width {
			out = append(out, line)
			continue
		}
		words := strings.Fields(line)
		current := ""
		for _, word := range words {
			if len(current)+len(word)+1 > width {
				out = append(out, current)
				current = word
			} else if current == "" {
				current = word
			} else {
				current += " " + word
			}
		}
		if current != "" {
			out = append(out, current)
		}
	}
	return out
}

func escapePDF(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	value = strings.ReplaceAll(value, ")", "\\)")
	return value
}
