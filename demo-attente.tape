# Le retour d'information pendant une commande longue :
#   vhs demo-attente.tape     (github.com/charmbracelet/vhs)
Output demo-attente.gif

Require bash
Set Shell bash
Set FontFamily "DejaVu Sans Mono"
Set FontSize 15
Set Width 1040
Set Height 480
Set Padding 22
Set Framerate 24
Set TypingSpeed 55ms
Set Theme { "background": "#1a1a1a", "foreground": "#d4d4d4", "cursor": "#d97757", "black": "#1a1a1a", "red": "#d95f5f", "green": "#87af87", "yellow": "#d7af5f", "blue": "#87afaf", "magenta": "#af87af", "cyan": "#87afaf", "white": "#d4d4d4", "brightBlack": "#767676", "brightRed": "#d95f5f", "brightGreen": "#87af87", "brightYellow": "#d7af5f", "brightBlue": "#87afaf", "brightMagenta": "#af87af", "brightCyan": "#87afaf", "brightWhite": "#eeeeee" }

# Décor, hors champ.
Hide
Type "export PS1='$ ' TERM=xterm-256color" Enter
Type "rm -rf /tmp/att && mkdir -p /tmp/att && cd /tmp/att" Enter
Type "echo VEtfVEVNT0lOPTIKVEtfT1BFUkFURVVSPSJNLiBCYWNobWFubiIKY2FsY3VsZXJfdmFyaWFibGVzKCkgewogICAgVEtfU1VKRVQ9IlBDMjMgwrcgQjEzIMK3IFBSSiDCtyBMSU5VWCIKICAgIFRLX1BSRUZJWD0iUEMyM19CMTNfUFJKX0xJTlVYIgogICAgVEtfREVUQUlMUz0oIm1vbnRhZ2U9L21udC9pbnZlc3RpZ2F0aW9uIiAic291cmNlPS9kZXYvbWFwcGVyL2NyeXB0MCIpCiAgICBESVJfVElNRUxJTkU9IiRQV0QvVElNRUxJTkUiCiAgICBESVJfTE9HUz0iJFBXRCIKfQpkZWZpbmlyX2NvbW1hbmRlcygpIHsKVEtfQ09NTUFOREVTPSgKImZscyBzdXIgL2Rldi9tYXBwZXIvY3J5cHQwfHRydWV8c2xlZXAgNyAmJiBwcmludGYgJ3IvciAxMDQzOlx0L2V0Yy9zaGFkb3dcbnIvciAxMDQ0Olx0L3Zhci9sb2cvYXV0aC5sb2dcbnIvciAxMDUxOlx0L2hvbWUvbGl6Ly5iYXNoX2hpc3RvcnlcbicgfCB0ZWUgJyRESVJfVElNRUxJTkUvUEMyMy5mbHMnIHwgdGFpbCAtbiAzIgoiaWxzLCBtw6ptZSBwYXJ0aXRpb258dHJ1ZXxzbGVlcCA1ICYmIHByaW50ZiAnMTA0M3xhfDB8MHwxNzg4OTQwMzUzXG4xMDQ0fGF8MHwwfDE3ODg5NDA0MTJcbicgfCB0ZWUgJyRESVJfVElNRUxJTkUvUEMyMy5pbHMnIHwgdGFpbCAtbiAyIgopClRLX0xJU1RFUz0oKQp9Cg== | base64 -d > d.conf" Enter
Type "clear" Enter
Show

Sleep 700ms
Type "/home/user/tasker.sh/tasker.sh -c d.conf"
Sleep 600ms
Enter
Sleep 2500ms

# L'opérateur valide. La commande est muette sept secondes :
# « lancée à », puis le compteur qui tourne sur place.
Enter
Sleep 9s

# Deuxième étape, même chose.
Enter
Sleep 7s

Sleep 2s
