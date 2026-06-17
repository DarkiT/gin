package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type moduleInfo struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

func main() {
	format := flag.String("format", "markdown", "输出格式: markdown 或 json")
	flag.Parse()

	rep, err := buildReport()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gincompat: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(os.Stderr, "gincompat: 编码 JSON 失败: %v\n", err)
			os.Exit(1)
		}
	case "markdown", "md":
		fmt.Print(renderMarkdown(rep))
	default:
		fmt.Fprintf(os.Stderr, "gincompat: 不支持的输出格式 %q\n", *format)
		os.Exit(1)
	}
}

func buildReport() (*report, error) {
	localModule, err := loadCurrentModule()
	if err != nil {
		return nil, err
	}
	upstreamModule, err := loadModule("github.com/gin-gonic/gin")
	if err != nil {
		return nil, err
	}
	localDir, err := loadPackageDir(localModule.Path)
	if err != nil {
		return nil, err
	}

	localExports, err := collectPackageExports(localDir)
	if err != nil {
		return nil, fmt.Errorf("读取本地公开符号失败: %w", err)
	}
	upstreamExports, err := collectPackageExports(upstreamModule.Dir)
	if err != nil {
		return nil, fmt.Errorf("读取上游公开符号失败: %w", err)
	}
	subpackages, err := compareSubpackages(localModule.Path, upstreamModule.Path)
	if err != nil {
		return nil, err
	}

	return &report{
		LocalModulePath: localModule.Path,
		LocalPackageDir: localDir,
		UpstreamModule:  upstreamModule.Path,
		UpstreamVersion: upstreamModule.Version,
		UpstreamDir:     upstreamModule.Dir,
		Package:         comparePackageExports(localExports, upstreamExports),
		Subpackages:     subpackages,
		NamedTypes:      compareNamedTypes(),
		Methods:         compareAllMethods(),
	}, nil
}

func compareSubpackages(localModule, upstreamModule string) ([]subpackageReport, error) {
	names := []string{"binding", "render", "codec/json", "ginS"}
	reports := make([]subpackageReport, 0, len(names))
	for _, name := range names {
		localImport := localModule + "/" + name
		upstreamImport := upstreamModule + "/" + name
		localDir, err := loadPackageDir(localImport)
		if err != nil {
			return nil, fmt.Errorf("读取本地子包 %s 目录失败: %w", localImport, err)
		}
		upstreamDir, err := loadPackageDir(upstreamImport)
		if err != nil {
			return nil, fmt.Errorf("读取上游子包 %s 目录失败: %w", upstreamImport, err)
		}
		localExports, err := collectPackageExports(localDir)
		if err != nil {
			return nil, fmt.Errorf("读取本地子包 %s 公开符号失败: %w", localImport, err)
		}
		upstreamExports, err := collectPackageExports(upstreamDir)
		if err != nil {
			return nil, fmt.Errorf("读取上游子包 %s 公开符号失败: %w", upstreamImport, err)
		}
		reports = append(reports, subpackageReport{
			Name:           name,
			LocalImport:    localImport,
			UpstreamImport: upstreamImport,
			LocalDir:       localDir,
			UpstreamDir:    upstreamDir,
			Package:        comparePackageExports(localExports, upstreamExports),
		})
	}
	return reports, nil
}

func loadCurrentModule() (*moduleInfo, error) {
	out, err := runGo("list", "-m", "-json")
	if err != nil {
		return nil, fmt.Errorf("读取当前模块信息失败: %w", err)
	}
	var info moduleInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("解析当前模块信息失败: %w", err)
	}
	return &info, nil
}

func loadModule(module string) (*moduleInfo, error) {
	out, err := runGo("list", "-m", "-json", module)
	if err != nil {
		return nil, fmt.Errorf("读取模块 %s 信息失败: %w", module, err)
	}
	var info moduleInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("解析模块 %s 信息失败: %w", module, err)
	}
	return &info, nil
}

func loadPackageDir(importPath string) (string, error) {
	out, err := runGo("list", "-f", "{{.Dir}}", importPath)
	if err != nil {
		return "", fmt.Errorf("读取包 %s 目录失败: %w", importPath, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func runGo(args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Env = os.Environ()
	return cmd.CombinedOutput()
}
