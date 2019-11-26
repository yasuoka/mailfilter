メールフィルター
================

作業中

```lua
mailserver = mailfilter.pop3("pop3s://mailserver", "username")
mailserver:getpass()

inbox = mailfilter.mh_folder("inbox")
spam  = mailfilter.mh_folder("spam")

for _,msg in pairs(mailserver:list()) do
  spam = false
  msg:top({
    on_header = function(key, val)
      if key == "subject" and val:find("未承諾広告") then
	spam = true
      end
    end
  })
  if not spam then
    inbox:save(msg, {"X-Spam-Check", "passed")
  else
    spam:save(msg)
  end
end
```

Mailfilter
==========

WIP

