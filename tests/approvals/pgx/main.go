package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const dsn = "postgres://ec2-user@127.0.0.1:5547/fw_appr_e2e?sslmode=disable&application_name=agent:support-agent:mission:pgx"
const api = "http://127.0.0.1:18099/api/holds"

var fails []string
var total int

func check(name string, ok bool, detail string) {
	total++
	s := "PASS"
	if !ok {
		s = "FAIL"
		fails = append(fails, name)
	}
	fmt.Println(s, name, detail)
}

func decide(action string, delay time.Duration) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(delay)
		for i := 0; i < 40; i++ {
			resp, err := http.Get(api)
			if err == nil {
				var out struct{ Holds []struct{ ID string } }
				json.NewDecoder(resp.Body).Decode(&out)
				resp.Body.Close()
				if len(out.Holds) > 0 {
					r, _ := http.Post(api+"/"+out.Holds[0].ID+"/"+action, "application/json", strings.NewReader(`{"by":"pgx-e2e"}`))
					if r != nil {
						r.Body.Close()
					}
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	return done
}

func status(ctx context.Context, id int) string {
	c, err := pgx.Connect(ctx, strings.Replace(dsn, "support-agent", "reader", 1))
	if err != nil {
		return "ERR " + err.Error()
	}
	defer c.Close(ctx)
	var s string
	c.QueryRow(ctx, "select status from orders where id=$1", id).Scan(&s)
	return s
}

func code(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return fmt.Sprint(err)
}

func main() {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Println("connect:", err)
		os.Exit(2)
	}
	defer c.Close(ctx)
	// reset rows
	r, _ := pgx.Connect(ctx, strings.Replace(dsn, "support-agent", "reader", 1))
	r.Exec(ctx, "update customers set name='c' where false")
	r.Close(ctx)

	// approve
	d := decide("approve", time.Second)
	tag, err := c.Exec(ctx, "update orders set status=$1 where id=$2", "pgx-ok", 4)
	<-d
	check("approve", err == nil && tag.RowsAffected() == 1 && status(ctx, 4) == "pgx-ok", fmt.Sprint(err))

	// deny + statement cache (2nd exec has no Parse)
	for i := 1; i <= 2; i++ {
		d = decide("deny", 300*time.Millisecond)
		_, err = c.Exec(ctx, "update orders set status=$1 where id=$2", "pgx-denied", 5)
		<-d
		check(fmt.Sprintf("deny (cached stmt run %d) -> 42501", i), code(err) == "42501" && status(ctx, 5) != "pgx-denied", code(err))
	}
	var x int
	check("conn reusable after deny", c.QueryRow(ctx, "select 1").Scan(&x) == nil && x == 1, "")

	// txn deny -> 25P02
	tx, _ := c.Begin(ctx)
	d = decide("deny", 300*time.Millisecond)
	_, err = tx.Exec(ctx, "update orders set status=$1 where id=$2", "pgx-txn", 6)
	<-d
	err2 := tx.QueryRow(ctx, "select 1").Scan(&x)
	check("txn deny -> 42501 then 25P02", code(err) == "42501" && code(err2) == "25P02", code(err)+" / "+code(err2))
	check("txn rollback ok", tx.Rollback(ctx) == nil && status(ctx, 6) == "open", "")

	// statement_timeout shorter than the hold
	c.Exec(ctx, "set statement_timeout='1s'")
	d = decide("approve", 2500*time.Millisecond)
	tag, err = c.Exec(ctx, "update orders set status=$1 where id=$2", "pgx-st", 7)
	<-d
	check("statement_timeout 1s, approved at 2.5s -> runs", err == nil && status(ctx, 7) == "pgx-st", fmt.Sprint(err))
	c.Exec(ctx, "set statement_timeout=0")

	// batch (pipeline): 3 stmts, 1 Sync, middle held, deny
	b := &pgx.Batch{}
	b.Queue("update customers set name=$1 where id=$2", "batch1", 1)
	b.Queue("update orders set status=$1 where id=$2", "batch", 9)
	b.Queue("select 1")
	d = decide("deny", 300*time.Millisecond)
	err = c.SendBatch(ctx, b).Close()
	<-d
	check("batch deny -> 42501, held row unchanged", code(err) == "42501" && status(ctx, 9) == "open", code(err))
	check("conn reusable after batch", c.QueryRow(ctx, "select 1").Scan(&x) == nil, "")

	// ctx timeout while held: pgx cancels + closes; must never run
	c2, _ := pgx.Connect(ctx, dsn)
	tctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, err = c2.Exec(tctx, "update orders set status=$1 where id=$2", "pgx-ghost", 2)
	cancel()
	time.Sleep(300 * time.Millisecond)
	resp, _ := http.Get(api)
	var out struct{ Holds []any }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	check("ctx deadline -> hold dropped, never runs", err != nil && len(out.Holds) == 0 && status(ctx, 2) == "open", fmt.Sprintf("err=%v holds=%d", err, len(out.Holds)))
	c2.Close(ctx)

	fmt.Printf("\n%d/%d passed %v\n", total-len(fails), total, fails)
	if len(fails) > 0 {
		os.Exit(1)
	}
}
