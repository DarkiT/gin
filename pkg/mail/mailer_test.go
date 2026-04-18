package mail

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sendHookFunc func(to string, subject, body string, isHTML bool, opts ...MailOption) error

func TestMailerSendBatch_PartialFailure(t *testing.T) {
	mailer := &Mailer{}
	mailer.setSendHook(sendHookFunc(func(to string, subject, body string, isHTML bool, opts ...MailOption) error {
		if to == "bad@example.com" {
			return errors.New("send failed")
		}
		return nil
	}))

	result, err := mailer.SendBatch([]string{"ok1@example.com", "bad@example.com", "ok2@example.com"}, "标题", "内容")
	if err == nil {
		t.Fatalf("expected batch error")
	}
	if result == nil {
		t.Fatalf("expected batch result")
	}
	if result.Total != 3 || result.Succeeded != 2 || result.Failed != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if len(result.Errors) != 1 || result.Errors["bad@example.com"] == nil {
		t.Fatalf("expected error for bad@example.com")
	}
}

func TestMailerSendBatch_ContinueOnErrorFalse(t *testing.T) {
	var sent int32
	mailer := &Mailer{}
	mailer.setSendHook(sendHookFunc(func(to string, subject, body string, isHTML bool, opts ...MailOption) error {
		atomic.AddInt32(&sent, 1)
		if to == "bad@example.com" {
			return errors.New("send failed")
		}
		return nil
	}))

	result, err := mailer.SendBatch([]string{"ok1@example.com", "bad@example.com", "ok2@example.com"}, "标题", "内容", WithContinueOnError(false))
	if err == nil {
		t.Fatalf("expected batch error")
	}
	if result == nil {
		t.Fatalf("expected batch result")
	}
	if result.Failed != 1 {
		t.Fatalf("expected one failure, got %+v", result)
	}
	if atomic.LoadInt32(&sent) == 3 {
		t.Fatalf("expected early stop when continueOnError is false")
	}
}

func TestMailerSendBatch_Concurrent(t *testing.T) {
	var active int32
	var maxActive int32
	var mu sync.Mutex
	seen := make(map[string]struct{})
	maxConcurrent := int32(2)

	mailer := &Mailer{}
	mailer.setSendHook(sendHookFunc(func(to string, subject, body string, isHTML bool, opts ...MailOption) error {
		current := atomic.AddInt32(&active, 1)
		if current > maxConcurrent {
			atomic.AddInt32(&active, -1)
			return fmt.Errorf("exceeded max concurrency: %d", current)
		}
		for {
			prev := atomic.LoadInt32(&maxActive)
			if current <= prev {
				break
			}
			if atomic.CompareAndSwapInt32(&maxActive, prev, current) {
				break
			}
		}

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		seen[to] = struct{}{}
		mu.Unlock()
		atomic.AddInt32(&active, -1)
		return nil
	}))

	recipients := []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com"}
	result, err := mailer.SendBatch(recipients, "标题", "内容", WithMaxConcurrent(int(maxConcurrent)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Succeeded != len(recipients) {
		t.Fatalf("unexpected success count: %+v", result)
	}
	if atomic.LoadInt32(&maxActive) < 2 {
		t.Fatalf("expected concurrent sends, got maxActive=%d", maxActive)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(recipients) {
		t.Fatalf("expected all recipients sent, got %d", len(seen))
	}
}

func TestMailerSendBatch_InvalidRecipient(t *testing.T) {
	mailer := &Mailer{}
	mailer.setSendHook(sendHookFunc(func(to string, subject, body string, isHTML bool, opts ...MailOption) error {
		return fmt.Errorf("unexpected send: %s", to)
	}))

	if _, err := mailer.SendBatch(nil, "标题", "内容"); !errors.Is(err, ErrMailToMissing) {
		t.Fatalf("expected ErrMailToMissing, got %v", err)
	}
}
