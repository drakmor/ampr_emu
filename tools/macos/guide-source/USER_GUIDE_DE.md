# Inhaltsverzeichnis

## Zwei Bedienwege

Auto Guide führt dich mit erklärenden Fenstern durch den Ablauf. Mit den manuellen Buttons startest du jeden Vorgang selbst. Beide Wege verwenden das Projekt und seine Sicherungen. Python ist enthalten; Terminalbefehle sind nicht nötig.

## Seite 2: Auto Guide starten

Spiel und Arbeitsordner auswählen. Entscheiden, ob du bereits eine TOML hast.

## Seite 3: Auf der PS5 aufzeichnen

Aufnahmeversion vorbereiten, spielen und die Aufzeichnung automatisch sichern.

## Seite 4: Profil und Bestätigung

TOML und Ausgabeordner erstellen, Profil laden und ungepackte Dateien bestätigen.

## Seite 5: Erstellen, prüfen und abschließen

Fortschritt verfolgen, Prüfung auswählen und das vollständige PAK-Spiel erstellen.

## Seite 6: Manuell arbeiten

Alle fünf Pfade selbst wählen und einzelne Vorgänge starten.

## Seite 7: EMU-Dateien aktualisieren

Aufnahmeversion, PAK-Version oder eine Datei für ein manuelles Update auswählen.

## Seite 8: Close, Continue, Step Back und Stop

Pausieren, fortsetzen, einen Schritt zurückgehen oder einen Vorgang abbrechen.

## Seite 9: Recovery und Aufräumen

Das Original wiederherstellen und später den Arbeitsordner entfernen.

# Auto Guide starten

## App öffnen

Öffne AMPR Pack Tools.app und klicke auf Auto Guide. Alle Schritte verwenden denselben Fensterstil. OK führt weiter, Close pausiert. Step Back geht einen Schritt zurück und macht die für diesen Schritt gespeicherten Änderungen rückgängig.

## Step 1: Spiel auswählen

Wähle deinen vollständigen Spieleordner. Er kann intern oder auf einem externen Laufwerk liegen. Hast du Game folder im Hauptfenster schon ausgewählt, verwendet der Guide diesen Pfad. Beginne mit dem vollständigen Original, nicht mit einem bereits verkleinerten PAK-Spiel.

## Step 2: Arbeitsordner auswählen

Wähle einen Ordner außerhalb des Spiels und außerhalb der Orte, die dein PS5-Loader nach Spielen durchsucht. Bei externen Laufwerken beginnt das Auswahlfenster auf der obersten Laufwerksebene. Gehe zuerst zum gewünschten Ort und nutze dann New Folder. Hier landen Projekt, Aufzeichnungen, Ausgabe und Originalsicherung.

## Step 3: TOML-Frage beantworten

Die App fragt vor der Indexerstellung, ob bereits eine TOML vorhanden ist. Hörst du zum ersten Mal davon, klicke No. Hast du eine passende Vorlage für dieses Spiel, klicke Yes und wähle sie aus.

## So wird gespeichert

Im Arbeitsordner entsteht <Name des Spieleordners>.json. Erledigte Schritte und der nächste Schritt werden automatisch gespeichert. Behalte auch den versteckten Ordner .ampr-projects. Die Projektdatei dokumentiert den Ablauf; sie ersetzt keine vollständige Spielsicherung.

## Zu den Schrittnummern

Die App nummeriert den gewählten Ablauf. Mit einer vorhandenen TOML entfallen Aufzeichnung und Profilerstellung. Die späteren Nummern sind dann niedriger. Diese Anleitung nennt deshalb die Aktionen, damit du beiden Wegen folgen kannst.

# Auf der PS5 aufzeichnen

## Spieldateien vorbereiten

Beide Abläufe prüfen fakelib, libSceAmpr.sprx und ampr_emu.index. Fehlende Ordner werden angelegt. Vorhandene SPRX und Index werden vor dem Austausch gesichert. Der Index wird aus dem vollständigen Spiel neu erstellt, nicht aus der SPRX. Die Änderungen werden für Step Back und Recovery gespeichert.

## Welche Version wird installiert?

Ohne TOML installiert die App die Aufnahmeversion (test-debug-pack). Mit vorhandener TOML installiert sie direkt die PAK-fähige Version ohne Aufzeichnung (test-pack); das Spielen für eine Aufnahme entfällt. Beide werden als fakelib/libSceAmpr.sprx eingesetzt. Dein PS5-Loader wird dadurch nicht eingerichtet.

## Record on your PS5

Nach der Vorbereitung folgst du diesem Fenster. Wirf ein externes Spielelaufwerk sicher aus und schließe es an die PS5 an. Spiele für eine erste Aufzeichnung etwa 5-10 Minuten. Probiere verschiedene Orte und Aktionen aus. Eine kurze Runde deckt nicht das gesamte Spiel ab.

## WICHTIG: Erst danach auf OK klicken

Beende das Spiel normal. Schließe das Laufwerk wieder am Mac an, unter demselben Pfad. Klicke erst jetzt auf OK. Der nächste Schritt sichert die Aufzeichnung. Close pausiert den Guide; du musst danach nicht von vorne beginnen.

## Die Aufzeichnung wird automatisch gesichert

Die App erstellt Recordings im Arbeitsordner und darin einen Unterordner mit Datum und Uhrzeit. Sie kopiert ampr_commands.bin und den passenden ampr_emu.index sowie ampr_emu.log, falls vorhanden. Es erscheint keine weitere Ordnerauswahl. Die Dateien im Spieleordner bleiben erhalten.

## Wenn du zwischen Geräten kopierst

Bringe Befehlsdatei, passenden Index und optionales Log der Spielrunde in den Spieleordner des Projekts zurück, bevor du fortfährst. Vermische keine Aufzeichnungen und Indizes verschiedener Spiele oder Updates. Bei einer vorhandenen TOML entfällt diese Aufnahmephase.

# Profil und Bestätigung

## Profil und Ausgabeort erstellen

Der Guide erklärt, dass er eine TOML mit dem Namen deines Spiels und einen Ordner Pack Output im Arbeitsordner erstellt. Klicke auf OK. Vorhandene Dateien werden nicht überschrieben; bei Bedarf bekommt der Name eine Nummer. Eine zuvor gewählte vorhandene TOML bleibt erhalten.

## Profil aus der Aufzeichnung erzeugen

Beim Aufnahmeweg erklärt das nächste Fenster die Profilerstellung. Mit OK wird die gespeicherte Aufzeichnung ausgewertet. Diese Aufzeichnungen heißen auch Traces. Die App füllt die TOML und erstellt Bericht und Messdaten. Danach erscheint eine separate Erfolgsmeldung.

## Profil laden und prüfen

Nach OK lädt und prüft der Guide das Profil. Du musst im Hauptfenster nicht selbst Load from profile suchen. Geprüft werden Konfiguration und verfügbarer Speicherbedarf. Damit wird nicht bestätigt, dass jede Szene, Sprache oder jeder DLC funktioniert.

## Ungepackte Dateien bestätigen

Das Fenster erklärt, dass nicht gepackte Dateien als normale Dateien im fertigen Spiel bleiben. Setze das Häkchen bei I understand. Keep unselected files loose und klicke auf Accept and start. Im Guide startet damit die PAK-Erstellung.

## Wenn du ablehnst

Es startet nichts. Das Projekt bleibt bei der Bestätigung. Über Continue erscheint sie erneut. Auch Close pausiert an dieser Stelle.

## Warum das wichtig ist

Die Aufzeichnung enthält nur Dateizugriffe aus deiner Spielrunde. Nicht erfasste Dateien werden nicht einfach gelöscht. Beim Abschluss übernimmt die App alle tatsächlich nicht gepackten Dateien, ausgenommen Aufzeichnungen und Sicherungsdateien der Vorbereitung.

# Erstellen, prüfen und abschließen

## Fortschritt verfolgen

Im Guide bleibt ein eigenes Fenster mit Fortschritt und geschätzter Restzeit sichtbar. Close blendet es aus, während der Vorgang weiterläuft. Mit Stop forderst du einen Abbruch an. Einzelheiten stehen weiterhin im Hauptprotokoll.

## Prüfung auswählen

Nach dem Erstellen wählst du Verify oder Skip verification. Verify liest die PAK-Daten und vergleicht sie mit den Originaldateien. Das dauert zusätzlich. Skip überspringt diesen Bytevergleich. Struktur und Speicherbedarf werden weiterhin geprüft; das Ergebnis wird ausdrücklich als UNVERIFIED gekennzeichnet.

## Finish PAK game

Die App erstellt in PAK Output einen Ordner mit dem Namen deines Spiels. Sie verschiebt die fertigen PAKs hinein und kopiert nur die übrigen ungepackten Spieldateien dazu. Danach verschiebt sie das Original nach Original game im Arbeitsordner und setzt das fertige PAK-Spiel an den bisherigen Spielort.

## Emulator und Indizes

Die App setzt fakelib/libSceAmpr.sprx durch die PAK-fähige Version ohne Aufzeichnung ein. NoPack ist für ein PAK-Spiel die falsche Variante. ampr_commands.bin und ampr_emu.log werden nicht übernommen. ampr_emu.index bleibt unverändert; baue ihn nicht anhand des verkleinerten Spiels neu auf. Die Zusatzdateien von ampr_assets.index gehören dazu.

## Auf Success warten

100 % beim Packen heißt noch nicht, dass der Abschluss fertig ist. Warte auf das abschließende Success-Fenster, bevor du ein Laufwerk trennst. Die App wirft Laufwerke nicht automatisch aus. Teste danach das fertige Spiel auf der PS5.

## Platz für beide Fassungen

Beim Verschieben innerhalb eines Volumes ist keine zweite PAK-Kopie nötig. Zwischen verschiedenen Volumes müssen die Daten übertragen werden; das dauert länger. Für die ungepackten Dateien und eine mögliche Übertragung muss genügend Platz frei sein. Lösche keine Originaldateien.

# Manuell arbeiten

## Pfade selbst auswählen

Browse gibt es für Game folder, ampr_emu.index, Trace directory, TOML profile und PAK output directory. Du kannst Pfade auch eingeben. Ein manuell gewählter Index muss zum Spiel und seinen Datei-IDs passen. Nutze New Project zum Wechseln des Spiels, statt einen vorhandenen Recovery-Eintrag umzubiegen.

## Kein automatischer Guide

Die manuellen Buttons starten ihre jeweiligen Vorgänge. Dabei beginnt kein Guide. Ergebnisse stehen im Protokoll; Fehler und nötige Bestätigungen erscheinen als Meldungen. Auto Guide und Continue sind eigene Funktionen.

## Profil manuell erstellen

Speichere oder wähle ein Aufnahme-Archiv, gib TOML-Dateiname und Ausgabeordner an und klicke auf Generate profile from traces. Load from profile zeigt die Dateimuster. Bei Bedarf kannst du Dateien ergänzen oder Muster entfernen. Danach Save selection und Check profile.

## Accept startet im manuellen Modus noch nicht

Fehlt das Häkchen, verlangt Create PAKs and verify eine Bestätigung. Accept setzt das Häkchen, startet aber nichts. Klicke anschließend selbst erneut auf Create PAKs and verify. Bei Decline bleibt der Vorgang angehalten.

## Vorhandene PAKs prüfen

Wähle Originalspiel, passenden Index, TOML und den vorhandenen PAK-Ausgabeordner. Verify existing PAKs vergleicht dieses Ergebnis mit den Originalen. Finish PAK game ist im manuellen Modus eine separate Aktion.

## Nach einem Abbruch fortsetzen

Das Projekt merkt sich den offenen Vorgang. Nach dem Aufräumen kann Continue ihn erneut starten. Ein abgebrochener PAK-Bau beginnt von vorne; er setzt nicht mitten in einer komprimierten Datei fort.

# EMU-Dateien aktualisieren

## Neue Versionen hinzufügen

Emulator files legt fest, welche libSceAmpr.sprx-Version die App benutzt. Der normale Auto Guide wählt die mitgelieferten Versionen bereits automatisch. Für eine andere Version wählst du eine heruntergeladene SPRX oder legst sie in den emus-Ordner. Diese Auswahl verändert noch keine Spieldateien.

## Die Aufgabe auswählen

Recording zeichnet Dateizugriffe beim Spielen auf. PAK game liest die PAK-Dateien im fertigen Spiel, ohne aufzuzeichnen. Das ist mit PAK runtime gemeint. Manual update wählt eine Version für einen separaten Austausch. Auswahl und Datei-Fingerabdruck werden im Projekt gespeichert.

## Dateinamen sind Hinweise

No-Pack und kein Debug sind zwei verschiedene Eigenschaften. Eine reine Versionsnummer beweist beides nicht. Bekannte mitgelieferte Dateien werden anhand ihres Inhalts erkannt. Bei unbekannten Versionen bestätigst du anhand der Veröffentlichung, ob PAKs und Aufzeichnung unterstützt werden. Für PAK-Versionen wird auch die dokumentierte Speicherpool-Größe abgefragt.

## Update emulator only

Wähle das Spiel, klicke auf Update emulator only und wähle die SPRX. Ein fehlender fakelib-Ordner wird angelegt. Eine vorhandene libSceAmpr.sprx wird gesichert. Der Index wird dabei nicht neu erstellt.

## Create / rebuild index

Erstellt ampr_emu.index aus den Spieldateien und sichert einen vorhandenen Index. libSceAmpr.sprx wird nicht geändert. Benutze das nicht für ein verkleinertes PAK-Spiel: Ein neuer Index würde die Zuordnung der Datei-IDs ändern.

## Set up both

Installiert die gewählte SPRX in fakelib und erstellt den Index. Nutze dafür ein vollständiges Originalspiel. Fehlende Dateien werden angelegt, vorhandene gesichert. Neue Emulatorversionen können andere Formate oder Anforderungen haben. Ein erkannter Dateiname allein garantiert deshalb keine Kompatibilität.

# Close, Continue, Step Back und Stop

## Einen wartenden Schritt schließen

Close pausiert den Guide. Der nächste Schritt bleibt im JSON-Projekt gespeichert. Open Project lädt ihn nach einem Neustart wieder. Continue bringt dich an diese Stelle zurück.

## Step Back

Step Back stellt die Einstellungen und Dateiänderungen des vorherigen Schritts zurück. Entfernt werden nur für diesen Schritt registrierte neue Dateien. Vorher vorhandene Dateien werden wiederhergestellt. Fremde Dateien in einem gemeinsam genutzten Ordner werden nicht mitgelöscht.

## Während eines Vorgangs

Der Guide hat ein eigenes Fortschrittsfenster, der manuelle Modus das große Protokoll. Beide bieten Stop. Das Ausblenden eines Fortschrittsfensters bricht nichts ab. Lass die Laufwerke angeschlossen, bis der Vorgang oder sein Aufräumen beendet ist.

## Zwei Stufen vor dem Abbruch

Zuerst bestätigst du die Stop-Warnung. Danach läuft ein Countdown über zehn Sekunden mit Cancel. Cancel verwirft den Abbruchwunsch; die Arbeit läuft weiter. Nach dem Countdown stoppt der Vorgang. Seine gespeicherten Änderungen werden rückgängig gemacht, sofern ein Schritt-Sicherungspunkt vorhanden ist.

## PAK-Erstellung abbrechen

Der Bau verwendet einen eigenen Zwischenordner. Beim Abbruch werden nur dieser Zwischenstand und die von diesem Bau erzeugten Ausgabedateien entfernt. Dein Originalspiel bleibt erhalten. Continue startet erneut. Das Rückgängigmachen eines unterbrochenen Spielabschlusses kann wegen der Ordnerwiederherstellung länger dauern.

## Ältere Projekte und Unterbrechungen

Schritte älterer App-Versionen können ohne einzelne Sicherungspunkte vorliegen. Die App kann diese Historie nicht nachträglich erfinden. Dann kann vollständige Recovery nötig sein. Schließe fehlende Laufwerke zuerst wieder an. Öffne dasselbe Projekt nicht gleichzeitig in zwei App-Versionen.

# Recovery und Aufräumen

## Recovery ist eine separate Aktion

Recovery läuft am Ende des Guides nicht automatisch. Klicke nur auf Recover original game, wenn du die Projektänderungen zurücknehmen willst. Die Warnung erklärt, dass der beim Anlegen erfasste Zustand wiederhergestellt wird.

## Bestätigung und Countdown

Wähle Yes. Danach bleiben zehn Sekunden zum Abbrechen mit Cancel. Recovery stellt zuerst das Original wieder her. Erst wenn das erfolgreich war, entfernt sie die vom Projekt erzeugten PAKs, Aufzeichnungen und temporären Dateien endgültig. Das PAK-Spiel wird nicht archiviert.

## Was entfernt wird und was bleibt

Erzeugte Dateien und gespeicherter Fortschritt werden entfernt. Importierte und vorher vorhandene Dateien bleiben erhalten. Unbekannte Dateien werden nicht gelöscht. Auf demselben Volume wird das Original zurückverschoben; zwischen Volumes ist eine Übertragung nötig. Ein kleiner Projektstatus bleibt. Mit New Project kannst du denselben Arbeitsordner erneut verwenden.

## Recovery für später behalten

Bis zur Recovery müssen Projektdatei, versteckter .ampr-projects-Ordner, Originalsicherung und zugehörige Dateien an ihren gespeicherten Orten bleiben. Nach erfolgreicher Wiederherstellung und Bereinigung ist das Projekt zurückgesetzt. Step Back bleibt eine separate Aktion, die benötigte Dateien zum Weiterarbeiten behält.

## Nach einem erfolgreichen PS5-Test

Die abschließende Meldung zeigt deinen tatsächlichen Arbeitsordner. Brauchst du weder Recovery noch weitere Projektarbeit, kannst du den dafür angelegten Arbeitsordner selbst löschen. Prüfe vorher, dass darin keine fremden Daten liegen und dass er kein übergeordneter Ordner des fertigen Spiels ist. Ohne Originalsicherung entfällt diese Recovery-Möglichkeit.

## Zu dieser Mac-Version

Nur für Apple Silicon. Python und LZ4 sind enthalten. Die App ist lokal signiert, aber nicht von Apple notarisiert. Diese Überarbeitung wurde auf Wunsch ohne weitere App-, PAK- oder PS5-Testläufe gebaut. Teste mit aufbewahrtem Original. UPSTREAM-Dokumente sind technische Referenzen, nicht dieser neue Bedienablauf.