// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"io/fs"
	"net/http"

	staticpkg "github.com/darkit/gin/pkg/static"
)

// Assets 设置当前路由组下基于本地目录的受控静态资源挂载。
func (r *Router) Assets(relativePath, root string, opts ...staticpkg.Option) IRoutes {
	return r.AssetsFS(relativePath, http.Dir(root), opts...)
}

// Site 设置当前路由组下基于本地目录的站点资源挂载。
func (r *Router) Site(relativePath, root string, opts ...staticpkg.Option) IRoutes {
	return r.SiteFS(relativePath, http.Dir(root), opts...)
}

// AssetsFS 设置当前路由组下基于文件系统的受控静态资源挂载。
func (r *Router) AssetsFS(relativePath string, fileSystem http.FileSystem, opts ...staticpkg.Option) IRoutes {
	if r == nil || r.engine == nil {
		return r
	}
	r.engine.AssetsFS(joinObservedPath(r.BasePath(), relativePath), fileSystem, opts...)
	return r
}

// SiteFS 设置当前路由组下基于文件系统的站点资源挂载。
func (r *Router) SiteFS(relativePath string, fileSystem http.FileSystem, opts ...staticpkg.Option) IRoutes {
	if r == nil || r.engine == nil {
		return r
	}
	r.engine.SiteFS(joinObservedPath(r.BasePath(), relativePath), fileSystem, opts...)
	return r
}

// AssetsZip 设置当前路由组下基于 ZIP 文件的受控静态资源挂载。
func (r *Router) AssetsZip(relativePath, zipPath string, opts ...staticpkg.Option) error {
	if r == nil || r.engine == nil {
		return nil
	}
	return r.engine.AssetsZip(joinObservedPath(r.BasePath(), relativePath), zipPath, opts...)
}

// SiteZip 设置当前路由组下基于 ZIP 文件的站点资源挂载。
func (r *Router) SiteZip(relativePath, zipPath string, opts ...staticpkg.Option) error {
	if r == nil || r.engine == nil {
		return nil
	}
	return r.engine.SiteZip(joinObservedPath(r.BasePath(), relativePath), zipPath, opts...)
}

// AssetsEmbeddedZip 设置当前路由组下基于嵌入式 ZIP 的受控静态资源挂载。
func (r *Router) AssetsEmbeddedZip(relativePath string, archive fs.FS, archivePath string, opts ...staticpkg.Option) error {
	if r == nil || r.engine == nil {
		return nil
	}
	return r.engine.AssetsEmbeddedZip(joinObservedPath(r.BasePath(), relativePath), archive, archivePath, opts...)
}

// SiteEmbeddedZip 设置当前路由组下基于嵌入式 ZIP 的站点资源挂载。
func (r *Router) SiteEmbeddedZip(relativePath string, archive fs.FS, archivePath string, opts ...staticpkg.Option) error {
	if r == nil || r.engine == nil {
		return nil
	}
	return r.engine.SiteEmbeddedZip(joinObservedPath(r.BasePath(), relativePath), archive, archivePath, opts...)
}
