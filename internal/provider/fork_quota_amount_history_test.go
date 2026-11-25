package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/plugin"
)

func TestQuotaAmountHistorySeparatesCountsFromAllowance(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	reset := start.AddDate(0, 1, 0)
	card := func(value float64, known bool) SubscriptionQuota {
		return quotaOfPlugin(SubscriptionQuota{Provider: "example-plugin", User: "example"}, plugin.Usage{Windows: []plugin.UsageWindow{{
			Name: "Credits", Amount: value, AmountKnown: known, Unit: "credits", Display: "used",
			ResetsAt: reset.Format(time.RFC3339), Span: reset.Sub(start).Seconds(),
		}}})
	}
	sample := func(reading SubscriptionQuota, at time.Time) {
		noteQuotaHistory([]SubscriptionQuota{reading}, at)
	}
	amounts := func(reading SubscriptionQuota, at time.Time) []BalancePoint {
		return WithQuotaAmountHistory([]SubscriptionQuota{reading}, at)[0].Windows[0].AmountTrend
	}
	at := start.Add(23*time.Hour + 59*time.Minute)
	sample(card(0, false), at.Add(-time.Hour))
	first := card(0, true)
	sample(first, at)
	second := card(10, true)
	sample(second, at.Add(2*time.Minute))
	withinGap := card(11, true)
	sample(withinGap, at.Add(4*time.Minute))
	stale := card(1000, true)
	stale.AsOf = &at
	sample(stale, at.Add(15*time.Minute))
	third := card(13.5, true)
	sample(third, at.Add(20*time.Minute))
	points := amounts(third, at.Add(20*time.Minute))
	if len(points) != 3 || points[0].Amount != 0 || points[1].Amount != 10 || points[2].Amount != 13.5 {
		t.Fatalf("cumulative usage = %+v, want real zero, midnight crossing, and later reading, not missing, in-gap, or stale ones", points)
	}
	if len(third.Windows[0].AmountTrend) != 0 || !third.Windows[0].Text || !third.Windows[0].Aside || len(QuotaHistories(start, third.Provider, third.User)) != 0 {
		t.Fatal("an amount must not alter the original card or become a quota share")
	}
	remote := third
	remote.From = "other-host"
	if len(WithQuotaAmountHistory([]SubscriptionQuota{remote}, at.Add(20*time.Minute))[0].Windows[0].AmountTrend) != 0 {
		t.Fatal("remote card must not receive local cumulative history")
	}
	start, reset = reset, reset.AddDate(0, 1, 0)
	next := card(2, true)
	sample(next, start)
	if points := amounts(next, start); len(points) != 1 || points[0].Amount != 2 {
		t.Fatalf("new cycle = %+v, want only its own reading", points)
	}
}

func TestQuotaAmountHistoryKeepsUnparsedFileAside(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := quotaAmountPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	reset := start.AddDate(0, 1, 0)
	reading := quotaOfPlugin(SubscriptionQuota{Provider: "example-plugin", User: "example"}, plugin.Usage{Windows: []plugin.UsageWindow{{
		Name: "Credits", Amount: 42, AmountKnown: true, Unit: "credits", Display: "42",
		ResetsAt: reset.Format(time.RFC3339), Span: reset.Sub(start).Seconds(),
	}}})
	noteQuotaHistory([]SubscriptionQuota{reading}, start.Add(time.Hour))
	points := WithQuotaAmountHistory([]SubscriptionQuota{reading}, start.Add(time.Hour))[0].Windows[0].AmountTrend
	if len(points) != 1 || points[0].Amount != 42 {
		t.Fatalf("after corrupt file = %+v, want fresh sample", points)
	}
	matches, err := filepath.Glob(path + ".bad*")
	if err != nil || len(matches) == 0 {
		t.Fatalf("expected corrupt history backup beside %s, got %v (err=%v)", path, matches, err)
	}
}
