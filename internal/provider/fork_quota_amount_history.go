package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/filememo"
	"github.com/yetone/magpie/internal/lastgood"
)

var quotaAmountMu sync.Mutex

func quotaAmountPath() string {
	return filepath.Join(filepath.Dir(Path()), "quota-amount-history.json")
}

func quotaAmounts() balanceHist {
	hist, err := filememo.Read("quota-amount-history", quotaAmountPath(), func(data []byte) (balanceHist, error) {
		var hist balanceHist
		err := json.Unmarshal(data, &hist)
		return hist, err
	})
	if err != nil {
		return nil
	}
	return hist
}

func quotaAmountKey(card SubscriptionQuota, window QuotaWindow, at time.Time) string {
	if !window.Cumulative || card.Provider == "" || window.Name == "" || window.ResetsAt == nil || !at.Before(*window.ResetsAt) {
		return ""
	}
	key, _ := json.Marshal([5]string{card.Provider, strings.ToLower(card.User), window.LineName(), window.Unit, window.ResetsAt.UTC().Truncate(time.Second).Format(time.RFC3339)})
	return string(key)
}

func sameLocalDay(a, b time.Time, loc *time.Location) bool {
	y1, m1, d1 := a.In(loc).Date()
	y2, m2, d2 := b.In(loc).Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func noteQuotaAmounts(cards []SubscriptionQuota, now time.Time) {
	var readings map[string]BalancePoint
	for _, card := range cards {
		if card.Error != "" || card.AsOf != nil {
			continue
		}
		at := now
		if card.ReadAt != nil && !card.ReadAt.After(now) {
			at = *card.ReadAt
		}
		for _, window := range card.Windows {
			key := quotaAmountKey(card, window, at)
			if key == "" || at.Before(window.ResetsAt.Add(-window.Span)) {
				continue
			}
			if readings == nil {
				readings = map[string]BalancePoint{}
			}
			readings[key] = BalancePoint{At: at.UTC().Truncate(time.Second), Amount: window.Amount}
		}
	}
	if len(readings) == 0 {
		return
	}
	quotaAmountMu.Lock()
	defer quotaAmountMu.Unlock()
	base := quotaAmounts()
	var hist balanceHist
	for key, point := range readings {
		points := base[key]
		if len(points) > 0 {
			last := points[len(points)-1].At
			if !point.At.After(last) || (point.At.Sub(last) < quotaHistGap && sameLocalDay(point.At, last, now.Location())) {
				continue
			}
		}
		if hist == nil {
			hist = make(balanceHist, len(base)+len(readings))
			for name, series := range base {
				hist[name] = series
			}
		}
		hist[key] = append(slices.Clip(points), point)
	}
	if hist == nil {
		return
	}
	cut := now.Add(-quotaHistKept)
	for key, points := range hist {
		first, _ := slices.BinarySearchFunc(points, cut, func(point BalancePoint, cutoff time.Time) int { return point.At.Compare(cutoff) })
		if first == len(points) {
			delete(hist, key)
		} else {
			hist[key] = points[first:]
		}
	}
	path := quotaAmountPath()
	if data, err := json.Marshal(hist); err == nil && lastgood.KeepUnparsed(path, lastgood.Into[balanceHist]) == nil {
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		_ = writeFileAtomic(path, data)
	}
}

func WithQuotaAmountHistory(cards []SubscriptionQuota, now time.Time) []SubscriptionQuota {
	var hist balanceHist
	loaded := false
	var out []SubscriptionQuota
	for cardIndex, card := range cards {
		if card.Error != "" || card.From != "" {
			continue
		}
		var windows []QuotaWindow
		for index, window := range card.Windows {
			key := quotaAmountKey(card, window, now)
			if key == "" {
				continue
			}
			if !loaded {
				hist, loaded = quotaAmounts(), true
			}
			if len(hist[key]) == 0 {
				continue
			}
			if windows == nil {
				if out == nil {
					out = slices.Clone(cards)
				}
				windows = slices.Clone(card.Windows)
				out[cardIndex].Windows = windows
			}
			windows[index].AmountTrend = hist[key]
		}
	}
	if out == nil {
		return cards
	}
	return out
}
