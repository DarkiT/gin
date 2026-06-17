package main

import (
	"fmt"
	"strings"
)

func renderMarkdown(rep *report) string {
	var b strings.Builder
	b.WriteString("# Gin 上游公开面兼容矩阵\n\n")
	b.WriteString(fmt.Sprintf("- 本地模块：`%s`\n", rep.LocalModulePath))
	b.WriteString(fmt.Sprintf("- 本地包目录：`%s`\n", rep.LocalPackageDir))
	b.WriteString(fmt.Sprintf("- 上游模块：`%s %s`\n", rep.UpstreamModule, rep.UpstreamVersion))
	b.WriteString(fmt.Sprintf("- 上游目录：`%s`\n", rep.UpstreamDir))
	b.WriteString("- 复跑命令：`GOWORK=off go run ./internal/tools/gincompat -format markdown`\n\n")

	b.WriteString("## 总览\n\n")
	b.WriteString("| 范围 | 同步 | 已映射 | 缺失 | 本地新增 |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: |\n")
	b.WriteString(fmt.Sprintf(
		"| 根包导出符号 | %d | %d | %d | %d |\n",
		len(rep.Package.Synced), len(rep.Package.Mapped), len(rep.Package.Missing), len(rep.Package.LocalOnly),
	))
	b.WriteString(fmt.Sprintf(
		"| 同名类型身份 | %d | %d | 0 | 0 |\n",
		len(rep.NamedTypes.Synced), len(rep.NamedTypes.Divergent),
	))
	for _, methodRep := range rep.Methods {
		b.WriteString(fmt.Sprintf(
			"| %s 方法集 | %d | %d | %d | %d |\n",
			methodRep.TypeName,
			methodRep.SyncedCount,
			len(methodRep.Mapped),
			len(methodRep.UpstreamOnly),
			len(methodRep.LocalOnly),
		))
	}
	b.WriteString("\n")

	writeSymbolSection(
		&b,
		"## 缺失的上游根包公开名",
		rep.Package.Missing,
		[]string{"名称", "上游种类", "状态", "说明"},
		func(f symbolFinding) []string {
			return []string{fmt.Sprintf("`%s`", f.Name), fmt.Sprintf("`%s`", f.UpstreamKind), f.Status, f.Note}
		},
	)
	writeSymbolSection(
		&b,
		"## 已映射但非严格同步的根包公开名",
		rep.Package.Mapped,
		[]string{"名称", "上游种类", "本地种类", "状态", "说明"},
		func(f symbolFinding) []string {
			return []string{
				fmt.Sprintf("`%s`", f.Name),
				fmt.Sprintf("`%s`", f.UpstreamKind),
				fmt.Sprintf("`%s`", f.LocalKind),
				f.Status,
				f.Note,
			}
		},
	)
	writeTypeSection(&b, "## 同名类型身份差异", rep.NamedTypes.Divergent)
	writeSubpackageReports(&b, rep.Subpackages)

	for _, methodRep := range rep.Methods {
		writeMethodReport(&b, methodRep)
	}

	return b.String()
}

func writeMethodReport(b *strings.Builder, methodRep methodReport) {
	b.WriteString(fmt.Sprintf("## %s 方法签名差异\n\n", methodRep.TypeName))
	b.WriteString(fmt.Sprintf("- 本地方法集：`%s`\n", methodRep.LocalMethodSet))
	b.WriteString(fmt.Sprintf("- 上游对照类型：`%s`\n", methodRep.UpstreamType))
	if methodRep.Note != "" {
		b.WriteString(fmt.Sprintf("- 说明：%s\n", methodRep.Note))
	}
	b.WriteString("\n")
	writeMethodSection(b, "### 已映射方法", methodRep.Mapped)
	writeMethodSection(b, "### 不兼容方法", methodRep.Incompatible)
	writeMethodSection(b, "### 上游独有方法", methodRep.UpstreamOnly)
	writeMethodSection(b, "### 本地新增方法", methodRep.LocalOnly)
}

func writeSubpackageReports(b *strings.Builder, reports []subpackageReport) {
	b.WriteString("## 公开子包导出符号对齐\n\n")
	if len(reports) == 0 {
		b.WriteString("无。\n\n")
		return
	}
	b.WriteString("| 子包 | 同步 | 已映射 | 缺失 | 本地新增 |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: |\n")
	for _, rep := range reports {
		b.WriteString(fmt.Sprintf(
			"| `%s` | %d | %d | %d | %d |\n",
			rep.Name,
			len(rep.Package.Synced),
			len(rep.Package.Mapped),
			len(rep.Package.Missing),
			len(rep.Package.LocalOnly),
		))
	}
	b.WriteString("\n")

	for _, rep := range reports {
		writeSymbolSection(
			b,
			fmt.Sprintf("### `%s` 缺失的上游公开名", rep.Name),
			rep.Package.Missing,
			[]string{"名称", "上游种类", "状态", "说明"},
			func(f symbolFinding) []string {
				return []string{fmt.Sprintf("`%s`", f.Name), fmt.Sprintf("`%s`", f.UpstreamKind), f.Status, f.Note}
			},
		)
		if len(rep.Package.Mapped) == 0 {
			continue
		}
		writeSymbolSection(
			b,
			fmt.Sprintf("### `%s` 已映射公开名", rep.Name),
			rep.Package.Mapped,
			[]string{"名称", "上游种类", "本地种类", "状态", "说明"},
			func(f symbolFinding) []string {
				return []string{
					fmt.Sprintf("`%s`", f.Name),
					fmt.Sprintf("`%s`", f.UpstreamKind),
					fmt.Sprintf("`%s`", f.LocalKind),
					f.Status,
					f.Note,
				}
			},
		)
	}
}

func writeSymbolSection(
	b *strings.Builder,
	title string,
	rows []symbolFinding,
	headers []string,
	render func(symbolFinding) []string,
) {
	b.WriteString(title + "\n\n")
	if len(rows) == 0 {
		b.WriteString("无。\n\n")
		return
	}
	writeTableHeader(b, headers)
	for _, row := range rows {
		writeTableRow(b, render(row))
	}
	b.WriteString("\n")
}

func writeTypeSection(b *strings.Builder, title string, rows []typeFinding) {
	b.WriteString(title + "\n\n")
	if len(rows) == 0 {
		b.WriteString("无。\n\n")
		return
	}
	writeTableHeader(b, []string{"名称", "本地类型", "上游类型", "状态", "说明"})
	for _, row := range rows {
		writeTableRow(b, []string{
			fmt.Sprintf("`%s`", row.Name),
			fmt.Sprintf("`%s`", row.LocalType),
			fmt.Sprintf("`%s`", row.UpstreamType),
			row.Status,
			row.Note,
		})
	}
	b.WriteString("\n")
}

func writeMethodSection(b *strings.Builder, title string, rows []methodFinding) {
	b.WriteString(title + "\n\n")
	if len(rows) == 0 {
		b.WriteString("无。\n\n")
		return
	}
	writeTableHeader(b, []string{"方法", "本地签名", "上游签名", "状态", "说明"})
	for _, row := range rows {
		writeTableRow(b, []string{
			fmt.Sprintf("`%s`", row.Name),
			fmt.Sprintf("`%s`", row.LocalSignature),
			fmt.Sprintf("`%s`", row.UpstreamSignature),
			row.Status,
			row.Note,
		})
	}
	b.WriteString("\n")
}

func writeTableHeader(b *strings.Builder, headers []string) {
	b.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	separators := make([]string, len(headers))
	for i := range separators {
		separators[i] = "---"
	}
	b.WriteString("| " + strings.Join(separators, " | ") + " |\n")
}

func writeTableRow(b *strings.Builder, cells []string) {
	escaped := make([]string, len(cells))
	for i, cell := range cells {
		escaped[i] = strings.ReplaceAll(cell, "|", "\\|")
	}
	b.WriteString("| " + strings.Join(escaped, " | ") + " |\n")
}
