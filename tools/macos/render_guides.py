from pathlib import Path
import json,shutil
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,PageBreak,KeepTogether
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
w=Path(__file__).parent
out=w/'help-resources';out.mkdir(exist_ok=True)
ink=colors.HexColor('#203447');accent=colors.HexColor('#137b78')
title=ParagraphStyle('title',fontName='Helvetica-Bold',fontSize=23,leading=28,textColor=ink,spaceAfter=15)
head=ParagraphStyle('heading',fontName='Helvetica-Bold',fontSize=12.5,leading=16,spaceBefore=9,spaceAfter=4,textColor=ink)
body=ParagraphStyle('body',fontName='Helvetica',fontSize=12,leading=17,spaceAfter=7,textColor=colors.HexColor('#283645'))
kicker=ParagraphStyle('kicker',fontName='Helvetica-Bold',fontSize=9,leading=12,textColor=accent,spaceAfter=12)
def norm(s):return s.replace('…','...').replace('–','-').replace('—','-').replace('‑','-').replace('’',"'")
def foot(c,d):
 c.setStrokeColor(colors.HexColor('#d4dfe5'));c.line(44,41,551,41);c.setFillColor(ink);c.setFont('Helvetica',8)
 c.drawString(44,27,'AMPR PAK Tools  |  macOS  |  07.09.2026');c.drawRightString(551,27,str(d.page))
for lang in ['DE','EN']:
 pages=json.loads((w/'guide-source'/f'{lang}.json').read_text());story=[]
 for i,(label,sections) in enumerate(pages):
  if i:story.append(PageBreak())
  story.append(Paragraph('AMPR PAK TOOLS / '+('SCHRITT FÜR SCHRITT' if lang=='DE' else 'STEP BY STEP'),kicker));story.append(Paragraph(escape(norm(label)),title))
  for h,b in sections:story.append(KeepTogether([Paragraph(escape(norm(h)),head),Paragraph(escape(norm(b)),body)]))
 SimpleDocTemplate(str(out/f'USER_GUIDE_{lang}.pdf'),pagesize=(595,842),leftMargin=44,rightMargin=44,topMargin=40,bottomMargin=54,title=f'AMPR PAK Tools - {lang} Mac Guide',author='AMPR Mac tools').build(story,onFirstPage=foot,onLaterPages=foot)
 print(lang,'rendered')
