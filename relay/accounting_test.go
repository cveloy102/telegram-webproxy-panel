package session

import (
 "encoding/json"
 "os"
 "path/filepath"
 "sync"
 "testing"
 "time"
 "github.com/telegramdesktop/tproxy-server/internal/frame"
)

func TestAccountingPersistenceAddressAndShutdown(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"usage.json")
 t.Setenv("TPROXY_ACCOUNTING_FILE",path)
 configuration:=testConfig("127.0.0.1:1")
 manager:=NewManager(configuration,[32]byte{1})
 bootstrap,err:=manager.IssueBootstrap(&configuration.Profiles[0],"198.51.100.9");if err!=nil{t.Fatal(err)}
 created,err:=manager.Create(bootstrap,"198.51.100.9",frame.Encode(frame.Hello,0,[]byte{1}));if err!=nil{t.Fatal(err)}
 name:=configuration.Profiles[0].Name
 var wg sync.WaitGroup
 for i:=0;i<8;i++ {wg.Add(1);go func(){defer wg.Done();for n:=0;n<100;n++{manager.account.bytes(name,"198.51.100.9",100,true)}}()};wg.Wait()
 manager.NoteAddress(created.Token,"203.0.113.10")
 manager.account.bytes(name,"203.0.113.10",400,false)
 manager.flushAccounting()
 b,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 var file usageFile;if err=json.Unmarshal(b,&file);err!=nil{t.Fatal(err)}
 if len(file.Rows)!=2 || file.Rows[name+"|198.51.100.9"].Up!=80000 || file.Rows[name+"|203.0.113.10"].Down!=400 {t.Fatal("incorrect accounting")}
 if file.Rows[name+"|203.0.113.10"].Live!=1 {t.Fatal("missing online session")}
 manager.Shutdown();manager.Shutdown()
 loaded:=newAccounting(path)
 if loaded.file.Rows[name+"|203.0.113.10"].Live!=0 || loaded.file.Rows[name+"|198.51.100.9"].Up!=80000 {t.Fatal("reload lost counters or retained live sessions")}
 if time.Now().Unix()-loaded.file.Updated>10 {t.Fatal("stale accounting")}
}
