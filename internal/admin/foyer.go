package admin

import (
	"net/http"
	"strconv"

	"github.com/audemed44/gatehouse/internal/sleep"
)

// Gatehouse serves a card in the Foyer widget format
// (https://github.com/audemed44/foyer/blob/main/docs/app-widgets.md): hosts,
// the soonest certificate expiry, and sleeping apps with a Wake button.

type foyerStat struct {
	Label   string `json:"label"`
	Value   string `json:"value"`
	Unit    string `json:"unit,omitempty"`
	Caption string `json:"caption,omitempty"`
	Tone    string `json:"tone,omitempty"`
}

type foyerAction struct {
	Label   string `json:"label"`
	URL     string `json:"url"`
	Confirm string `json:"confirm,omitempty"`
}

type foyerItem struct {
	Title    string       `json:"title"`
	Subtitle string       `json:"subtitle,omitempty"`
	Caption  string       `json:"caption,omitempty"`
	URL      string       `json:"url,omitempty"`
	Action   *foyerAction `json:"action,omitempty"`
}

type foyerWidget struct {
	Version    int         `json:"version"`
	Stats      []foyerStat `json:"stats"`
	ItemsTitle string      `json:"items_title,omitempty"`
	Items      []foyerItem `json:"items"`
}

func (s *Server) foyerWidget(w http.ResponseWriter, _ *http.Request) {
	cfg := s.Proxy.Config()
	out := foyerWidget{Version: 1, Items: []foyerItem{}}
	enabled := 0
	for _, h := range cfg.Hosts {
		if h.Enabled {
			enabled++
		}
	}
	out.Stats = append(out.Stats, foyerStat{Label: "Hosts", Value: strconv.Itoa(enabled), Caption: plural(len(cfg.Redirects), "redirect", "redirects")})

	soonest := -1
	soonestName := ""
	for _, c := range s.certViews() {
		if c.Missing {
			continue
		}
		if soonest < 0 || c.DaysLeft < soonest {
			soonest, soonestName = c.DaysLeft, c.Name
		}
	}
	if soonest >= 0 {
		tone := ""
		switch {
		case soonest < 7:
			tone = "bad"
		case soonest < cfg.Settings.WarnDays:
			tone = "warn"
		}
		out.Stats = append(out.Stats, foyerStat{Label: "Certificate", Value: strconv.Itoa(soonest), Unit: "d", Caption: soonestName, Tone: tone})
	}

	var errs int64
	for _, st := range s.Proxy.Log.Stats() {
		if st.Host != "" {
			errs += st.Status5
		}
	}
	tone := ""
	if errs > 0 {
		tone = "warn"
	}
	out.Stats = append(out.Stats, foyerStat{Label: "5xx", Value: strconv.FormatInt(errs, 10), Caption: "since start", Tone: tone})

	if s.Sleep != nil {
		statuses := s.Sleep.Statuses()
		asleep := 0
		for _, st := range statuses {
			item := foyerItem{Title: st.Container, Subtitle: st.State, Caption: "idle stop " + st.IdleStop}
			if st.State != sleep.Awake {
				asleep++
				item.Action = &foyerAction{Label: "Wake", URL: "/api/foyer/wake/" + st.Container}
			}
			out.Items = append(out.Items, item)
		}
		if len(statuses) > 0 {
			out.Stats = append(out.Stats, foyerStat{Label: "Sleeping", Value: strconv.Itoa(asleep), Unit: "/" + strconv.Itoa(len(statuses))})
			out.ItemsTitle = "Scale to zero"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) foyerWake(w http.ResponseWriter, r *http.Request) {
	if s.Sleep == nil {
		fail(w, errNotFound)
		return
	}
	if err := s.Sleep.Wake(r.PathValue("container")); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Waking " + r.PathValue("container")})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
