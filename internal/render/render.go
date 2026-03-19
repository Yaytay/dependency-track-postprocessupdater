package render

import (
	"dependency-track-postprocessupdater/internal/store"
	"fmt"
	"net/http"
)

func WriteMetrics(w http.ResponseWriter, s store.Snapshot) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE postprocess_processed_total counter\n")
	fmt.Fprintf(w, "postprocess_processed_total %d\n", s.Processed)
}
