"""Byte progress reporting shared by the CLI and macOS front end."""
import sys
import time

class Progress:
 def __init__(self,label,total):self.label=label;self.total=total;self.done=0;self.start=time.monotonic();self.last=0;self(0)
 def __call__(self,n):
  self.done+=n;t=time.monotonic()
  if t-self.last<1 and self.done<self.total:return
  elapsed=t-self.start;rate=self.done/max(elapsed,.001);eta=(self.total-self.done)/rate if rate else None
  pct=100*self.done/max(self.total,1)
  print(f'[{self.label} {min(pct,100):.0f}%] {self.done/2**30:.2f} / {self.total/2**30:.2f} GiB | ETA '+(time.strftime('%H:%M:%S',time.gmtime(max(0,eta))) if eta is not None else 'calculating'),file=sys.stderr,flush=True);self.last=t
