package session

// Operator accounting is optional. It contains profile names and network
// metadata, never capabilities, session tokens, secrets or payloads.
import (
 "encoding/json"
 "log"
 "os"
 "sync"
 "time"
)

type usageBytes struct { Up uint64 `json:"up"`; Down uint64 `json:"down"` }
type usageRow struct {
 Profile string `json:"profile"`
 IP string `json:"ip"`
 First int64 `json:"first"`
 Connected int64 `json:"connected"`
 Last int64 `json:"last"`
 Connections uint64 `json:"connections"`
 Up uint64 `json:"up"`
 Down uint64 `json:"down"`
 Live int `json:"live"`
 Days map[string]*usageBytes `json:"days"`
 Hours map[string]*usageBytes `json:"hours"`
}
type usageFile struct {
 Started int64 `json:"started"`
 Updated int64 `json:"updated"`
 Rows map[string]*usageRow `json:"rows"`
}
type accounting struct { mu sync.Mutex; path string; file usageFile; done chan struct{} }

func newAccounting(path string) *accounting {
 a:=&accounting{path:path,done:make(chan struct{}),file:usageFile{Started:time.Now().Unix(),Rows:map[string]*usageRow{}}}
 if path!="" { if b,err:=os.ReadFile(path);err==nil { if json.Unmarshal(b,&a.file)!=nil || a.file.Rows==nil { panic("invalid operator accounting file") } } }
 for _,r:=range a.file.Rows { r.Live=0; if r.Days==nil {r.Days=map[string]*usageBytes{}}; if r.Hours==nil {r.Hours=map[string]*usageBytes{}} }
 return a
}
func(a *accounting) row(profile,ip string) *usageRow {
 key:=profile+"|"+ip
 r:=a.file.Rows[key]
 if r==nil {r=&usageRow{Profile:profile,IP:ip,First:time.Now().Unix(),Days:map[string]*usageBytes{},Hours:map[string]*usageBytes{}};a.file.Rows[key]=r}
 return r
}
func(a *accounting) opened(profile,ip string) {
 if a.path=="" {return};a.mu.Lock();defer a.mu.Unlock()
 r:=a.row(profile,ip);r.Connected=time.Now().Unix();r.Last=r.Connected;r.Connections++
}
func(a *accounting) bytes(profile,ip string,count int,up bool) {
 if a.path=="" || count<=0 {return};a.mu.Lock();defer a.mu.Unlock()
 r:=a.row(profile,ip);now:=time.Now();r.Last=now.Unix()
 day:=now.In(time.UTC).Format("2006-01-02");hour:=now.UTC().Format("2006-01-02T15")
 if r.Days[day]==nil {r.Days[day]=&usageBytes{}};if r.Hours[hour]==nil {r.Hours[hour]=&usageBytes{}}
 n:=uint64(count);if up {r.Up+=n;r.Days[day].Up+=n;r.Hours[hour].Up+=n}else{r.Down+=n;r.Days[day].Down+=n;r.Hours[hour].Down+=n}
}
func(m *Manager) flushAccounting() {
 a:=m.account;if a.path=="" {return}
 m.mu.Lock();sessions:=make([]*Session,0,len(m.sessions));for _,s:=range m.sessions {sessions=append(sessions,s)};m.mu.Unlock()
 type live struct{ profile,ip string; last int64 }; states:=make([]live,0,len(sessions));for _,s:=range sessions {states=append(states,live{s.profile.Name,s.accountIP.Load().(string),s.LastActivity().Unix()})}
 a.mu.Lock();defer a.mu.Unlock();now:=time.Now();a.file.Updated=now.Unix()
 for _,r:=range a.file.Rows {r.Live=0;for h:=range r.Hours {if h<now.Add(-48*time.Hour).UTC().Format("2006-01-02T15"){delete(r.Hours,h)}};for d:=range r.Days {if d<now.AddDate(0,0,-90).In(time.UTC).Format("2006-01-02"){delete(r.Days,d)}}}
 for _,s:=range states {r:=a.row(s.profile,s.ip);if s.last>r.Last {r.Last=s.last};if now.Unix()-s.last<=90 {r.Live++}}
 b,err:=json.Marshal(a.file);if err!=nil{return}
 tmp:=a.path+".tmp";err=os.WriteFile(tmp,b,0640);if err==nil{err=os.Rename(tmp,a.path)};if err!=nil{log.Print("event=accounting_write_failed")}
}
func(m *Manager) NoteAddress(token,ip string) {
 if m.account.path=="" {return}; s,err:=m.Get(token);if err!=nil{return}
 if s.accountIP.Load().(string)!=ip {s.accountIP.Store(ip);m.account.opened(s.profile.Name,ip)}
}
func(m *Manager) accountingLoop() {
 defer close(m.account.done);if m.account.path=="" {return};ticker:=time.NewTicker(5*time.Second);defer ticker.Stop()
 m.flushAccounting()
 for {select {case <-ticker.C:m.flushAccounting();case <-m.stop:m.flushAccounting();return}}
}
