// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"context"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"

	staticpkg "github.com/darkit/gin/pkg/static"
)

type staticMount struct {
	prefix  string
	service *staticpkg.Service
}

type staticStopper interface {
	Stop()
}

func (e *Engine) needsManagedNoRoute() bool {
	return e != nil && (e.regexRouter != nil || len(e.staticMounts) > 0)
}

func (e *Engine) registerStaticMount(prefix string, service *staticpkg.Service) {
	if e == nil || service == nil {
		return
	}

	normalized := normalizeStaticMountPrefix(prefix)
	for i, mount := range e.staticMounts {
		if mount.prefix == normalized {
			e.staticMounts[i] = &staticMount{
				prefix:  normalized,
				service: service,
			}
			e.registerNoRouteIfUnset()
			return
		}
	}

	e.staticMounts = append(e.staticMounts, &staticMount{
		prefix:  normalized,
		service: service,
	})
	sort.SliceStable(e.staticMounts, func(i, j int) bool {
		return len(e.staticMounts[i].prefix) > len(e.staticMounts[j].prefix)
	})
	e.registerNoRouteIfUnset()
}

func (e *Engine) tryServeStaticMounts(c *GinContext) bool {
	if e == nil || c == nil || len(e.staticMounts) == 0 {
		return false
	}

	requestPath := requestLookupPath(c.Request)
	for _, mount := range e.staticMounts {
		subPath, ok := matchStaticMount(mount.prefix, requestPath)
		if !ok {
			continue
		}
		return mount.service.TryServePath(c.Writer, c.Request, subPath)
	}

	return false
}

func (e *Engine) trackStaticStopper(stopper staticStopper) {
	if e == nil || stopper == nil {
		return
	}
	e.OnStopped(func(context.Context) error {
		stopper.Stop()
		return nil
	})
}

func normalizeStaticMountPrefix(prefix string) string {
	raw := strings.TrimSpace(prefix)
	if raw == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}

	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == "/" {
		return "/"
	}
	return strings.TrimSuffix(cleaned, "/")
}

func normalizeStaticRequestPath(requestPath string) string {
	if requestPath == "" {
		return "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	cleaned := path.Clean(requestPath)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func matchStaticMount(prefix, requestPath string) (string, bool) {
	normalizedPrefix := normalizeStaticMountPrefix(prefix)
	normalizedRequest := normalizeStaticRequestPath(requestPath)
	if normalizedPrefix == "/" {
		return normalizedRequest, true
	}
	if normalizedRequest == normalizedPrefix {
		return "/", true
	}
	if strings.HasPrefix(normalizedRequest, normalizedPrefix+"/") {
		subPath := strings.TrimPrefix(normalizedRequest, normalizedPrefix)
		if subPath == "" {
			subPath = "/"
		}
		return subPath, true
	}
	return "", false
}

// Assets 设置基于本地目录的受控静态资源挂载。
func (e *Engine) Assets(relativePath, root string, opts ...staticpkg.Option) IRoutes {
	return e.AssetsFS(relativePath, http.Dir(root), opts...)
}

// Site 设置基于本地目录的站点资源挂载。
func (e *Engine) Site(relativePath, root string, opts ...staticpkg.Option) IRoutes {
	return e.SiteFS(relativePath, http.Dir(root), opts...)
}

// AssetsFS 设置基于文件系统的受控静态资源挂载。
func (e *Engine) AssetsFS(relativePath string, fileSystem http.FileSystem, opts ...staticpkg.Option) IRoutes {
	if e == nil || fileSystem == nil {
		return e
	}
	e.registerStaticMount(relativePath, staticpkg.NewAssetsService(fileSystem, opts...))
	return e
}

// SiteFS 设置基于文件系统的站点资源挂载。
func (e *Engine) SiteFS(relativePath string, fileSystem http.FileSystem, opts ...staticpkg.Option) IRoutes {
	if e == nil || fileSystem == nil {
		return e
	}
	e.registerStaticMount(relativePath, staticpkg.NewSiteService(fileSystem, opts...))
	return e
}

// AssetsZip 设置基于 ZIP 文件的受控静态资源挂载。
func (e *Engine) AssetsZip(relativePath, zipPath string, opts ...staticpkg.Option) error {
	config := staticpkg.NewZipFSConfig(zipPath, relativePath, opts...)
	fileSystem, err := staticpkg.NewZipFileSystem(config)
	if err != nil {
		return err
	}
	e.trackStaticStopper(fileSystem)
	e.AssetsFS(relativePath, fileSystem, opts...)
	return nil
}

// SiteZip 设置基于 ZIP 文件的站点资源挂载。
func (e *Engine) SiteZip(relativePath, zipPath string, opts ...staticpkg.Option) error {
	config := staticpkg.NewZipFSConfig(zipPath, relativePath, opts...)
	fileSystem, err := staticpkg.NewZipFileSystem(config)
	if err != nil {
		return err
	}
	e.trackStaticStopper(fileSystem)
	e.SiteFS(relativePath, fileSystem, opts...)
	return nil
}

// AssetsEmbeddedZip 设置基于嵌入式 ZIP 的受控静态资源挂载。
func (e *Engine) AssetsEmbeddedZip(relativePath string, archive fs.FS, archivePath string, opts ...staticpkg.Option) error {
	fileSystem, err := staticpkg.NewEmbeddedZipFS(archive, archivePath, opts...)
	if err != nil {
		return err
	}
	e.AssetsFS(relativePath, fileSystem, opts...)
	return nil
}

// SiteEmbeddedZip 设置基于嵌入式 ZIP 的站点资源挂载。
func (e *Engine) SiteEmbeddedZip(relativePath string, archive fs.FS, archivePath string, opts ...staticpkg.Option) error {
	fileSystem, err := staticpkg.NewEmbeddedZipFS(archive, archivePath, opts...)
	if err != nil {
		return err
	}
	e.SiteFS(relativePath, fileSystem, opts...)
	return nil
}

// FallbackSite 设置全局站点兜底挂载。
func (e *Engine) FallbackSite(root string, opts ...staticpkg.Option) IRoutes {
	return e.FallbackSiteFS(http.Dir(root), opts...)
}

// FallbackSiteFS 设置全局站点兜底挂载。
func (e *Engine) FallbackSiteFS(fileSystem http.FileSystem, opts ...staticpkg.Option) IRoutes {
	return e.SiteFS("/", fileSystem, opts...)
}

// FallbackSiteZip 设置基于 ZIP 文件的全局站点兜底挂载。
func (e *Engine) FallbackSiteZip(zipPath string, opts ...staticpkg.Option) error {
	return e.SiteZip("/", zipPath, opts...)
}

// FallbackSiteEmbeddedZip 设置基于嵌入式 ZIP 的全局站点兜底挂载。
func (e *Engine) FallbackSiteEmbeddedZip(archive fs.FS, archivePath string, opts ...staticpkg.Option) error {
	return e.SiteEmbeddedZip("/", archive, archivePath, opts...)
}
