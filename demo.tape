# Enregistrement de la démonstration du README :
#   vhs demo.tape     (github.com/charmbracelet/vhs)
Output demo.gif

Require bash
Set Shell bash
Set FontFamily "DejaVu Sans Mono"
Set FontSize 15
Set Width 1040
Set Height 720
Set Padding 22
Set Framerate 24
Set TypingSpeed 55ms
Set Theme { "background": "#1a1a1a", "foreground": "#d4d4d4", "cursor": "#d97757", "black": "#1a1a1a", "red": "#d95f5f", "green": "#87af87", "yellow": "#d7af5f", "blue": "#87afaf", "magenta": "#af87af", "cyan": "#87afaf", "white": "#d4d4d4", "brightBlack": "#767676", "brightRed": "#d95f5f", "brightGreen": "#87af87", "brightYellow": "#d7af5f", "brightBlue": "#87afaf", "brightMagenta": "#af87af", "brightCyan": "#87afaf", "brightWhite": "#eeeeee" }

# Un dossier de démonstration, hors champ.
Hide
Type "export HOME=/tmp/demo USER=demo PS1='$ ' TERM=xterm-256color" Enter
Type "rm -rf /tmp/demo /tmp/tasker; mkdir -p /tmp/demo/{documents,images,projets}" Enter
Type "head -c 3000000 /dev/urandom > /tmp/demo/images/photo.raw" Enter
Type "head -c 900000 /dev/urandom > /tmp/demo/documents/rapport.pdf" Enter
Type "head -c 40000 /dev/urandom > /tmp/demo/projets/notes.md" Enter
Type "clear" Enter
Show

Sleep 800ms
Type "./tasker.sh"
Sleep 700ms
Enter
Sleep 3500ms

# Étape 2 : on valide.
Enter
Sleep 2500ms

# Étape 3 : répétée sur chaque sous-dossier.
Enter
Sleep 3s

# Étape 4 : la question devient un menu.
Sleep 1500ms
Type "1"
Sleep 600ms
Enter
Sleep 1500ms
Enter
Sleep 4s
