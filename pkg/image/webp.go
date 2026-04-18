package image

import (
	"image"
	"io"

	purewebp "github.com/deepteams/webp"
)

func encodeWebP(w io.Writer, img image.Image, quality int) error {
	return purewebp.Encode(w, img, &purewebp.Options{Quality: float32(quality)})
}
