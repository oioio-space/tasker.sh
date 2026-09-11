#!/usr/bin/env python3
"""Une collecte qui porte TOUS les artefacts, et la preuve qu'on en tire quelque chose.

    python3 tests/artefacts.py [dossier de travail]

Fabrique une collecte synthétique où chaque pièce que `collecte-linux.conf`
sait prendre est présente — et piégée : un film copié sur une clé USB, un
marque-page vers un site de torrent, une recherche tapée dans la barre
d'adresse, un mineur en autostart, une unité systemd qui lance depuis /tmp,
une clé SSH commune à deux comptes, un compte qui prend l'identité d'un
autre. Puis elle lance les deux extracteurs et VÉRIFIE que chaque artefact a
produit le fait ou le constat qu'on en attend.

C'est le filet de la couverture : `tests/matrice.py` répond « les cinq
familles de distributions passent-elles ? », celui-ci répond « chaque pièce
collectée sert-elle à quelque chose ? ». Ajouter une pièce à la collecte sans
l'ajouter ici, c'est ne pas la tester.

Sort 0 si tout est trouvé, 1 sinon, en disant ce qui manque.
"""
import calendar, gzip, io, json, os, re, shutil, sqlite3, subprocess, zipfile
import sys, tarfile, tempfile, time

ICI = os.path.dirname(os.path.abspath(__file__))
SKILLS = os.path.dirname(ICI)
sys.path.insert(0, os.path.join(SKILLS, "forensic-linux", "scripts"))
from extraire import UTMP                                              # noqa: E402

P = "PC42_B12_ARTE_ubuntu"
US = 1_000_000
EPOCH_1601 = 11_644_473_600


def epoch(iso):
    return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%S"))


def ff(iso):                       # Firefox, wtmpdb : microsecondes depuis 1970
    return epoch(iso) * US


def ch(iso):                       # Chrome : microsecondes depuis 1601
    return (epoch(iso) + EPOCH_1601) * US


def sqlite_blob(schema, rows):
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as t:
        nom = t.name
    cx = sqlite3.connect(nom)
    for sql in schema:
        cx.execute(sql)
    for sql, r in rows:
        cx.executemany(sql, r)
    cx.commit()
    cx.close()
    blob = open(nom, "rb").read()
    os.unlink(nom)
    return blob


def utmp(entrees):
    """wtmp binaire : type, pid, tty, compte, origine, date."""
    return b"".join(
        UTMP.pack(typ, pid, tty.encode().ljust(32, b"\0"), tty[-4:].encode().ljust(4, b"\0"),
                  qui.encode().ljust(32, b"\0"), ou.encode().ljust(256, b"\0"),
                  0, 0, 0, epoch(iso), 0, b"\0" * 16, b"\0" * 20)
        for typ, pid, tty, qui, ou, iso in entrees)


def batir(base):
    R = os.path.join(base, P)
    for d in ("SYSTEME", "COMPTES", "PAQUETS", "RESEAU", "JOURNAUX", "CONNEXIONS",
              "PERSISTANCE", "TIMELINE", "MACHINES", "PHOTOREC/recup_1", "STRINGS",
              "SUPPRIMES/racine"):
        os.makedirs(os.path.join(R, d), exist_ok=True)

    def w(rel, contenu):
        with open(os.path.join(R, rel), "wb") as fh:
            fh.write(contenu.encode("utf-8") if isinstance(contenu, str) else contenu)

    def T(rel, membres):
        """Un membre dont le contenu est un tuple ("lien", cible) est un LIEN
        symbolique : c'est ce que /etc/apparmor.d/disable/ contient, et rien
        d'autre — un test qui y mettrait un fichier ne testerait rien."""
        with tarfile.open(os.path.join(R, rel), "w:gz") as t:
            for nom, blob in membres.items():
                i = tarfile.TarInfo("./" + nom)
                i.mtime = epoch("2026-01-08T12:00:00")
                if isinstance(blob, tuple):
                    i.type, i.linkname, i.size = tarfile.SYMTYPE, blob[1], 0
                    t.addfile(i)
                    continue
                blob = blob.encode("utf-8") if isinstance(blob, str) else blob
                i.size = len(blob)
                t.addfile(i, io.BytesIO(blob))

    # ── le système ────────────────────────────────────────────────────
    w("SYSTEME/hostname", "pc42\n")
    w("SYSTEME/os-release", 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
                            'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n')
    w(f"SYSTEME/{P}_localtime.txt", "Europe/Paris\n")
    w("SYSTEME/fstab", "UUID=aaaa / ext4 defaults 0 1\n"
                       "//serveur/partage /mnt/partage cifs credentials=/root/.smb 0 0\n"
                       "/dev/mapper/coffre /coffre ext4 defaults 0 2\n")
    T(f"SYSTEME/{P}_installation.tar.gz", {
        "etc/machine-id": "9f1c3a2b4d5e6f708192a3b4c5d6e7f8\n",
        "etc/adjtime": "0.0 0 0.0\n0\nUTC\n",
        "root/anaconda-ks.cfg": "network --hostname=pc42.entreprise.fr\n"
                                "timezone Europe/Paris\nrootpw --iscrypted $6$x\n"
                                "user --name=jdupont --groups=wheel\n"})
    w(f"MACHINES/{P}_disques_virtuels.txt", "/home/jdupont/VM/kali.qcow2\n")

    # ── les paquets ───────────────────────────────────────────────────
    w(f"PAQUETS/{P}_paquets.txt",
      "||/ Nom Version Architecture Description\n+++-===\n"
      "ii  firefox 134.0 amd64 navigateur\n"
      "ii  qbittorrent 5.0.3 amd64 torrent\n")
    T(f"PAQUETS/{P}_historique.tar.gz", {
        "var/log/dpkg.log": "2025-06-01 08:00:00 install base-files:amd64 <none> 13.1\n"
                            "2026-01-04 18:30:00 install qbittorrent:amd64 <none> 5.0.3\n",
        "var/log/apt/history.log": "Start-Date: 2026-01-04  18:29:58\n"
                                   "Commandline: apt install qbittorrent\nEnd-Date: 2026-01-04  18:30:05\n"})

    # ── les comptes, leurs droits, leur PAM ───────────────────────────
    w(f"COMPTES/{P}_passwd.txt",
      "root:x:0:0:root:/root:/bin/bash\n"
      "jdupont:x:1000:1000:Jean Dupont:/home/jdupont:/bin/bash\n"
      "mrobert:x:1001:1001:M Robert:/home/mrobert:/bin/bash\n")
    T(f"COMPTES/{P}_droits.tar.gz", {
        "etc/shadow": "root:$6$a$b:19000:0:99999:7:::\njdupont:$1$c$d:19800:0:99999:7:::\n",
        "etc/sudoers": "%wheel ALL=(ALL) NOPASSWD: ALL\n",
        "etc/login.defs": "PASS_MAX_DAYS\t99999\n",
        "etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\n",
        "etc/pam.d/common-password":
            "# minlen ici serait un commentaire, pas une règle\n"
            "password requisite pam_pwquality.so retry=3 minlen=6 difok=2\n"
            "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n",
        "etc/apparmor.d/disable/usr.bin.firefox": ("lien", "/etc/apparmor.d/usr.bin.firefox")})
    w(f"COMPTES/{P}_jdupont_stat.txt",
      "  File: /mnt/i/home/jdupont\n  Size: 4096\nModify: 2026-01-06 22:31:00.000000000 +0100\n"
      " Birth: 2025-06-01 09:12:00.000000000 +0200\n")
    w(f"COMPTES/{P}_jdupont_inventaire.txt",
      "/mnt/i/home/jdupont:\ntotal 20\n"
      "drwxr-xr-x 8 jdupont jdupont 4096 janv.  6 22:31 .\n"
      "-rw------- 1 jdupont jdupont  812 janv.  4 10:22 .bash_history\n"
      "-rw-r--r-- 1 mrobert mrobert  512 janv.  5 11:02 note-de-mrobert.odt\n"
      "-rw-r--r-- 1 jdupont jdupont 3174 nov.  30 18:40 Le.Film.2024.VOSTFR.torrent\n"
      "\n/mnt/i/home/jdupont/Vidéos/Films:\ntotal 8\n"
      "-rw-r--r-- 1 jdupont jdupont 2147483648 déc.  24 22:05 Le.Film.2024.1080p.mkv\n")
    w(f"COMPTES/{P}_mrobert_inventaire.txt",
      "/mnt/i/home/mrobert:\ntotal 4\n"
      "-rw-r--r-- 1 mrobert mrobert 4096 janv.  3 17:12 rapport-2026.odt\n")

    cle = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPARTAGEEPARTAGEEPARTAGEEPARTAGEE0 "
           "cle-commune\n")
    # Firefox : historique, cookies, marque-pages, formulaires, mots de passe
    places = sqlite_blob(
        ["CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
         "visit_count INTEGER, last_visit_date INTEGER)",
         "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)",
         "CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, content TEXT, dateAdded INTEGER)",
         "CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, "
         "title TEXT, dateAdded INTEGER)"],
        [("INSERT INTO moz_places VALUES(?,?,?,?,?)", [
            (1, "https://www.yggtorrent.wtf/torrent/999", "Le.Film.2024", 1, ff("2025-11-30T18:38:00")),
            (2, "https://intranet.entreprise.fr/rh", "RH", 40, ff("2026-01-05T09:00:00")),
            # Une longue traîne de pages ANCIENNES. Une borne, quelle qu'elle
            # soit, garde les plus récentes et jette celles-ci — c'est-à-dire
            # exactement ce qu'on ne retrouve nulle part ailleurs quand
            # l'historique récent a été vidé. Le test les compte toutes.
            *((i, f"https://vieux-site-{i:03d}.example/page", f"Page {i}", 1,
               ff("2025-01-%02dT08:00:00" % (i % 28 + 1))) for i in range(3, 23))]),
         ("INSERT INTO moz_historyvisits VALUES(?,?,?)", [
            (1, 1, ff("2025-11-30T18:38:00")), (2, 2, ff("2025-06-01T09:00:00"))]),
         ("INSERT INTO moz_annos VALUES(?,?,?,?)", [
            (1, 1, "file:///home/jdupont/Téléchargements/Le.Film.2024.VOSTFR.torrent",
             ff("2025-11-30T18:40:00"))]),
         ("INSERT INTO moz_bookmarks VALUES(?,?,?,?,?)", [
            (1, 1, 1, "Le film", ff("2025-11-30T18:35:00"))])])
    T(f"COMPTES/{P}_jdupont_profils.tar.gz", {
        ".mozilla/firefox/ab.default/places.sqlite": places,
        ".mozilla/firefox/ab.default/cookies.sqlite": sqlite_blob(
            ["CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, host TEXT, name TEXT, "
             "value TEXT, creationTime INTEGER, lastAccessed INTEGER)"],
            [("INSERT INTO moz_cookies VALUES(?,?,?,?,?,?)", [
                (1, ".netflix.com", "sid", "NE-PAS-LIRE",
                 ff("2025-10-10T21:00:00"), ff("2025-12-24T22:00:00"))])]),
        ".mozilla/firefox/ab.default/formhistory.sqlite": sqlite_blob(
            ["CREATE TABLE moz_formhistory(id INTEGER PRIMARY KEY, fieldname TEXT, value TEXT, "
             "timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER)"],
            [("INSERT INTO moz_formhistory VALUES(?,?,?,?,?,?)", [
                (1, "q", "telecharger film gratuit", 3,
                 ff("2025-11-29T20:00:00"), ff("2025-11-30T18:30:00"))])]),
        ".mozilla/firefox/ab.default/logins.json": json.dumps({"logins": [
            {"hostname": "https://www.leboncoin.fr", "encryptedUsername": "x",
             "encryptedPassword": "y", "timeCreated": epoch("2025-12-02T13:06:00") * 1000,
             "timeLastUsed": epoch("2025-12-02T13:06:00") * 1000}]}),
        ".thunderbird/ab.default/prefs.js":
            'user_pref("mail.identity.id1.useremail", "jean.dupont@entreprise.fr");\n'
            'user_pref("mail.identity.id2.useremail", "jdupont1987@gmail.com");\n'
            'user_pref("mail.server.server2.hostname", "imap.gmail.com");\n',
        ".local/share/recently-used.xbel":
            '<bookmark href="file:///home/jdupont/V%C3%AD/Le.Film.2024.1080p.mkv" '
            'added="2025-12-24T22:06:00Z" modified="2025-12-24T22:06:00Z"/>',
        "snap/spotify/current/x": "x",
        ".var/app/com.valvesoftware.Steam/config/y": "y"})
    T(f"COMPTES/{P}_jdupont_artefacts.tar.gz", {
        ".bash_history": "ls -l\ncurl -u admin:Secr3t! https://intranet\n"
                         "#1767105600\nqbittorrent-nox -d\nsudo -u mrobert bash\n",
        ".ssh/authorized_keys": cle,
        ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                           + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZQ==\n"
                           + "-----END OPENSSH PRIVATE KEY-----\n",
        ".config/autostart/mineur.desktop":
            "[Desktop Entry]\nType=Application\nExec=/home/jdupont/.cache/xmrig -o pool:3333\n",
        ".config/google-chrome/Default/History": sqlite_blob(
            ["CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
             "visit_count INTEGER, last_visit_time INTEGER)",
             "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)",
             "CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, "
             "start_time INTEGER)",
             "CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT)"],
            [("INSERT INTO urls VALUES(?,?,?,?,?)", [
                (1, "https://papystreaming.example/film", "Film", 1, ch("2025-12-24T21:30:00"))]),
             ("INSERT INTO visits VALUES(?,?,?)", [(1, 1, ch("2025-12-24T21:30:00"))]),
             ("INSERT INTO downloads VALUES(?,?,?,?)", [
                (1, "/home/jdupont/Téléchargements/rustdesk-1.2.3.deb",
                 "https://rustdesk.com/", ch("2025-11-30T18:44:00"))]),
             ("INSERT INTO keyword_search_terms VALUES(?,?,?)",
              [(1, 1, "streaming film complet vf")])]),
        ".config/google-chrome/Default/Bookmarks": json.dumps({"roots": {"bookmark_bar": {
            "children": [{"type": "url", "name": "Papystreaming",
                          "url": "https://papystreaming.example/",
                          "date_added": str(ch("2025-12-24T21:00:00"))}]}}}),
        ".config/google-chrome/Default/Web Data": sqlite_blob(
            ["CREATE TABLE autofill(name TEXT, value TEXT, count INTEGER, "
             "date_created INTEGER, date_last_used INTEGER)"],
            [("INSERT INTO autofill VALUES(?,?,?,?,?)", [
                ("email", "jdupont1987@gmail.com", 4,
                 epoch("2025-10-20T12:00:00"), epoch("2026-01-03T08:00:00"))])])})
    T(f"COMPTES/{P}_mrobert_artefacts.tar.gz",
      {".bash_history": "make -j8\ngit push\n", ".ssh/authorized_keys": cle})
    T(f"COMPTES/{P}_mrobert_profils.tar.gz", {".mozilla/firefox/zz.default/places.sqlite":
                                              b"SQLite format 3\x00https://intranet.entreprise.fr/\x00"})

    # ── sessions, journal, réseau, persistance ────────────────────────
    w("CONNEXIONS/wtmp", utmp([
        (2, 0, "~", "reboot", "6.8.0", "2026-01-05T07:00:00"),
        (7, 1001, "tty2", "jdupont", "", "2026-01-05T07:12:00"),
        (7, 1002, "pts/0", "mrobert", "10.1.2.3", "2026-01-05T09:00:00"),
        (8, 1002, "pts/0", "", "", "2026-01-05T09:30:00"),
        (8, 1001, "tty2", "", "", "2026-01-05T16:00:00"),
        (7, 1003, "pts/1", "jdupont", "192.168.1.50", "2026-01-06T21:31:00")]))
    w(f"JOURNAUX/{P}_journal.txt",
      "2026-01-05T10:15:03+0100 pc42 sudo[42]: mrobert : TTY=pts/0 ; PWD=/ ; USER=root ; "
      "COMMAND=/usr/bin/apt install qbittorrent\n"
      "2026-01-05T11:40:10+0100 pc42 kernel: usb 1-2: New USB device found, idVendor=0781, idProduct=5583\n"
      "2026-01-05T11:40:10+0100 pc42 kernel: usb 1-2: SerialNumber: 4C530001230405112233\n"
      "2026-01-05T11:40:12+0100 pc42 udisksd[900]: Mounted /dev/sdb1 at "
      "/run/media/jdupont/SANDISK32 on behalf of uid 1000\n"
      "2026-01-05T18:40:00+0100 pc42 su: pam_unix(su:session): session opened for user "
      "mrobert(uid=1001) by jdupont(uid=1000)\n")
    # Le journal TOURNÉ, comprimé, RANGÉ DANS LE TAR : c'est la forme la plus
    # courante de tout /var/log, et le seul endroit où vit la chaîne ci-dessous.
    # Si les membres d'archive ne sont pas décomprimés avant d'être soumis aux
    # motifs, elle ressort « ABSENTE » — le pire mensonge que l'outil puisse
    # faire — alors qu'elle est là.
    T(f"JOURNAUX/{P}_var_log.tar.gz", {
        "var/log/auth.log":
            "Jan  5 09:00:01 pc42 sshd[7]: Accepted publickey for "
            "mrobert from 10.1.2.3 port 5000 ssh2\n",
        "var/log/auth.log.2.gz": gzip.compress(
            b"Jan  2 08:14:55 pc42 sudo: jdupont : "
            b"COMMAND=/usr/bin/journal-tourne-et-comprime-dans-le-tar\n")})
    T(f"RESEAU/{P}_reseau.tar.gz", {
        "etc/NetworkManager/system-connections/Bureau.nmconnection":
            "[connection]\nid=Bureau\nuuid=11111111-1111-1111-1111-111111111111\ntype=wifi\n"
            "\n[wifi]\nssid=ENTREPRISE-CORP\nmac-address=DC:A6:32:1B:4E:07\n",
        "etc/NetworkManager/system-connections/McDo.nmconnection":
            "[connection]\nid=McDonalds Free WiFi\n"
            "uuid=22222222-2222-2222-2222-222222222222\ntype=wifi\n"
            "permissions=user:jdupont:;\n\n[wifi]\nssid=McDonalds Free WiFi\n"
            # bit « administré localement » posé : une adresse tirée au hasard,
            # ce que fait un portable pour le Wi-Fi. La synthèse doit le DIRE,
            # sinon on croit suivre une machine alors qu'on suit un tirage.
            "cloned-mac-address=B2:7A:11:C0:FF:EE\n",
        "var/lib/NetworkManager/timestamps":
            "[timestamps]\n22222222-2222-2222-2222-222222222222=1766000000\n",
        "etc/wpa_supplicant/wpa_supplicant.conf": 'network={\n    ssid="ibis-hotel"\n}\n',
        "var/lib/iwd/=4d63446f20465220576946692e.psk": "[Security]\nPassphrase=x\n",
        "etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\n",
        "etc/hosts": "127.0.0.1 localhost\n10.0.0.9 depot-interne\n",
        "etc/resolv.conf": "nameserver 10.0.0.1\nsearch entreprise.local\n"})
    T(f"PERSISTANCE/{P}_persistance.tar.gz", {
        "etc/crontab": "0 3 * * * root /usr/bin/updatedb\n",
        "etc/systemd/system/collecte.service":
            "[Unit]\nDescription=collecte\n[Service]\nExecStart=/opt/outil/collecte --daemon\n",
        "etc/systemd/system/backdoor.service":
            "[Unit]\nDescription=maj\n[Service]\nExecStart=/tmp/.maj/agent\n",
        "usr/lib/systemd/system/cups.service": "[Service]\nExecStart=/usr/sbin/cupsd -l\n",
        "etc/xdg/autostart/verif.desktop": "[Desktop Entry]\nExec=/usr/bin/verif-maj\n",
        "etc/systemd/system/multi-user.target.wants/x.service":
            "[Service]\nExecStartPre=/opt/outil/prepare\nExecStart=/opt/outil/x\n",
        "usr/lib/systemd/system/deux-exec.service":
            "[Service]\nExecStartPre=/usr/bin/mkdir -p /run/x\nExecStart=/usr/sbin/x\n",
        "etc/udev/rules.d/99-usb.rules":
            '# exemple : RUN+="/bin/faux"\n'
            'ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/local/bin/note-usb.sh"\n'
            'ACTION=="add", SUBSYSTEM=="block", RUN{builtin}+="kmod load x"\n'})

    # ── la timeline, en ISO, dans le fuseau qu'on note à côté ─────────
    w(f"TIMELINE/{P}_fuseau_timeline.txt", "UTC\n")
    lignes = ["Date,Size,Type,Mode,UID,GID,Meta,File Name"]

    def tl(d, taille, genre, inode, chemin):
        lignes.append(f'{d},{taille},{genre},r/rrw-r--r--,1000,1000,{inode},"{chemin}"')

    for i in range(500):                                   # du bruit, comme une vraie
        tl(f"2025-12-{i % 28 + 1:02d}T0{i % 9}:00:00", 900, "m...", 100000 + i,
           f"/usr/share/doc/paquet{i}/README")
    tl("2025-11-30T18:40:02", 31742, "macb", 262146,
       "/home/jdupont/Téléchargements/Le.Film.2024.VOSTFR.torrent")
    tl("2025-11-30T18:44:12", 1048576, "macb", 262145,
       "/home/jdupont/Téléchargements/rustdesk-1.2.3.deb")
    tl("2025-12-24T22:05:00", 2147483648, "macb", 393217,
       "/home/jdupont/Vidéos/Films/Le.Film.2024.1080p.mkv")
    tl("2026-01-05T10:41:03", 2147483648, "...b", 8193,
       "/run/media/jdupont/SANDISK32/Le.Film.2024.1080p.mkv")
    tl("2026-01-05T10:42:10", 512, ".a..", 8194,
       "/run/media/jdupont/SANDISK32/procedure-interne.pdf")
    tl("2026-01-04T10:22:31", 812, "m.c.", 131074, "/home/jdupont/.bash_history")
    w(f"TIMELINE/{P}_mactime.csv", "\n".join(lignes) + "\n")

    # ── ce que photorec a rendu ───────────────────────────────────────
    # Deux pièces LISIBLES parmi le remplissage : c'est tout l'enjeu, un
    # fichier récupéré sans nom ni date reste du contenu, et l'outil doit
    # regarder dedans. La clé privée et le mot de passe en clair ne sont
    # nulle part ailleurs dans la collecte.
    for nom, taille in (("f0001.pdf", 50000), ("f0003.jpg", 800000),
                        ("f0004.kdbx", 4000), ("f0005.zip", 90000), ("f0006", 1000)):
        w(f"PHOTOREC/recup_1/{nom}", b"x" * taille)
    w("PHOTOREC/recup_1/f0002.txt",
      "notes de reprise\n"
      "-----BEGIN OPENSSH PRIVATE KEY-----\n"
      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
      "-----END OPENSSH PRIVATE KEY-----\n")
    w("PHOTOREC/recup_1/f0007.txt",
      "# brouillon de configuration retrouve dans l'espace libre\n"
      "smtp_host = smtp.entreprise.fr\n"
      "password = Bienvenue2025!\n")
    # Un .docx récupéré : un zip de XML. Sans décompression, les motifs n'y
    # voient RIEN alors que le texte est là — et c'est le cas le plus courant
    # de tout PHOTOREC, celui d'un document de bureautique.
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml",
                   "<w:t>Compte rendu</w:t>"
                   "<w:t>acces admin : password = SecretDansUnDocx!</w:t>")
    w("PHOTOREC/recup_1/f0008.docx", tampon.getvalue())
    # SUPPRIMES ne vient que de xfs_undelete, donc que d'un volume xfs : le
    # chemin existe dans le code depuis le début mais n'était jamais exercé.
    # Le nom que rend xfs_undelete porte la date de suppression et l'inode.
    w("SUPPRIMES/racine/2026-01-04_10-22-31_131074.txt",
      "Objet : reunion du 4 janvier\n"
      "Cordialement, jdupont@entreprise.fr\n"
      "acces au partage : //serveur/partage\n")

    # ── STRINGS : les chaînes des périphériques, deux volumes ─────────
    # DEUX volumes, sinon rien ne prouve que la collecte n'oublie pas le /home
    # monté à part — c'est exactement la garantie à tenir. Et le fichier brut
    # porte une chaîne qu'AUCUNE autre pièce ne contient : c'est le seul moyen
    # de vérifier qu'il est vraiment fouillé.
    #
    # Les extraits sont écrits LITTÉRALEMENT, au format que rend la collecte
    # (« compte décalage valeur »). Les dériver en Python reviendrait à
    # réécrire les motifs de la conf : le piège s'accorderait alors avec
    # lui-même quoi qu'il arrive, ce qui est le contraire d'un test.
    for volume, brut, extraits in (
        ("racine",
         ["https://www.yggtorrent.wtf/torrent/999",
          "jdupont1987@gmail.com",
          "10.0.0.9",
          "/home/jdupont/Téléchargements/Le.Film.2024.VOSTFR.torrent",
          "chaine-effacee-que-rien-d-autre-ne-porte",
          "AKIAIOSFODNN7EXAMPLE",
          "e8:9c:25:3f:0a:b1",
          "https://www.yggtorrent.wtf/torrent/999"],
         {"urls": "      2 https://www.yggtorrent.wtf/torrent/999\n",
          "courriels": "      1 jdupont1987@gmail.com\n",
          "ip": "      1 10.0.0.9\n",
          "mac": "      1 e8:9c:25:3f:0a:b1\n",
          "chemins": "      1 /home/jdupont/Téléchargements/Le.Film.2024.VOSTFR.torrent\n"}),
        ("home",
         ["/home/jdupont/Vidéos/Films/Le.Film.2024.1080p.mkv",
          "mrobert@entreprise.fr",
          "192.168.0.5"],
         {"chemins": "      1 /home/jdupont/Vidéos/Films/Le.Film.2024.1080p.mkv\n",
          "courriels": "      1 mrobert@entreprise.fr\n",
          "ip": "      1 192.168.0.5\n"}),
    ):
        # strings NU, non comprimé : ni décalage en tête de ligne, ni .gz.
        w(f"STRINGS/{P}_strings_{volume}.txt", "\n".join(brut) + "\n")
        for genre, contenu in extraits.items():
            w(f"STRINGS/{P}_strings_{volume}_{genre}.txt", contenu)

    # hors de la collecte : un fichier d'indicateurs posé DEDANS se trouverait
    # lui-même, et l'extracteur l'écarte — le test le vérifie en le posant à côté
    with open(os.path.join(base, "indicateurs.txt"), "w", encoding="utf-8") as fh:
        fh.write("# ce que l'on cherche, venu d'ailleurs\n"
                 "texte: McDonalds\nfichier: *.torrent\nip: 203.0.113.42   # jamais vue ici\n"
                 # celle-ci n'existe QUE dans le .gz : si l'extracteur ne
                 # décompresse pas en flux, elle sort « ABSENTE » et le test
                 # tombe. C'est le seul moyen de prouver que le strings du
                 # disque est réellement fouillé.
                 "texte: chaine-effacee-que-rien-d-autre-ne-porte\n"
                 # Cette chaîne est IMBRIQUÉE dans ce que reconnaît un motif de
                 # l'outil (« password = Bienvenue2025! »). Avec une alternation
                 # ordinaire, le motif interne l'avale et elle ressort
                 # « ABSENTE » — on annonce à l'analyste que sa preuve n'existe
                 # pas. C'est le pire faux négatif possible : le test l'interdit.
                 "texte: Bienvenue2025!\n"
                 # Celle-ci n'existe que dans un .gz RANGÉ DANS UN TAR. Le
                 # membre était soumis aux motifs sous sa forme comprimée, où
                 # rien ne peut correspondre : elle sortait « ABSENTE ».
                 "texte: journal-tourne-et-comprime-dans-le-tar\n")
    return R


# Ce que chaque artefact DOIT produire. Un fait attendu qui manque, c'est une
# pièce collectée pour rien.
ATTENDUS_FAITS = [
    ("fstab", "montage réseau déclaré"),
    ("kickstart", "compte créé à l'installation"),
    ("machine-id", "machine-id"),
    ("stat du dossier", "création du dossier du compte"),
    ("disque virtuel", "disque de machine virtuelle sur le poste"),
    ("paquets", "paquets installés (nombre)"),
    ("dpkg.log", "installation du système (plus ancienne ligne de dpkg.log)"),
    ("apt history", "commande du gestionnaire de paquets"),
    ("wtmp binaire", "ouverture de session"),
    ("wtmp : fermeture", "fermeture de session"),
    ("journal : sudo", "commande sudo"),
    ("journal : su", "changement d'utilisateur (su)"),
    ("journal : USB", "support amovible USB branché"),
    ("journal : série USB", "numéro de série du support USB"),
    ("journal : montage", "système de fichiers amovible monté"),
    ("auth.log tourné", "connexion SSH acceptée"),
    ("NetworkManager", "réseau sans fil enregistré"),
    ("hosts", "hôte déclaré en dur"),
    ("resolv.conf", "serveur DNS"),
    ("historique Firefox", "page visitée"),
    ("cookies", "domaine ayant posé un cookie"),
    ("téléchargements", "fichier téléchargé"),
    ("marque-pages", "marque-page enregistré"),
    ("formulaires", "saisie dans un formulaire"),
    ("recherches", "recherche saisie dans la barre d'adresse"),
    ("mots de passe enregistrés", "mot de passe enregistré dans le navigateur"),
    ("recently-used", "fichier ouvert récemment"),
    ("snap", "application snap présente chez ce compte"),
    ("flatpak", "application flatpak présente chez ce compte"),
    ("Thunderbird", "adresse de courriel configurée"),
    ("historique shell", "historique daté (HISTTIMEFORMAT posé)"),
    ("clé autorisée", "clé SSH autorisée à ouvrir ce compte"),
    ("autostart du compte", "programme lancé à l'ouverture de session de ce compte"),
    ("cron", "tâche planifiée"),
    ("unité posée à la main", "unité systemd posée par l'administrateur"),
    ("unité anormale", "unité systemd lançant un programme depuis un endroit anormal"),
    ("autostart du système", "programme lancé à l'ouverture de session"),
    ("udev", "règle udev lançant un programme"),
    ("photorec", "pièces récupérées de type « document »"),
    ("timeline : compte", "entrées dans la timeline du système de fichiers"),
    ("timeline : téléchargement", "fichier retrouvé sur le disque"),
    ("timeline : clé USB", "fichier écrit sur un support amovible"),
    ("timeline : lecture", "fichier lu sur un support amovible"),
    ("périodes : borne", "première trace datée de la collecte"),
    ("périodes : trou", "aucune trace pendant une longue période"),
    ("supports : regroupés", "support amovible reconnu"),
    ("chaînes : compte", "chaînes distinctes de type « adresse web »"),
    ("chaînes : url", "adresse web"),
    ("chaînes : courriel", "adresse de courriel"),
    ("chaînes : IP", "adresse IP"),
    ("chaînes : chemin", "chemin personnel"),
    ("chaînes : brut", "chaînes brutes du périphérique"),
    ("indicateur trouvé", "texte recherché présent dans un fichier"),
    ("indicateur absent", "ip recherché ABSENT de la collecte"),
]
ATTENDUS_CONSTATS = [
    ("shadow : MD5", "mot de passe haché en MD5 (algorithme obsolète)"),
    ("sudoers", "élévation sans mot de passe (sudo NOPASSWD)"),
    ("login.defs", "durée de vie des mots de passe très longue"),
    ("PAM : nullok", "PAM accepte un mot de passe vide (nullok)"),
    ("PAM : minlen en argument", "longueur minimale de mot de passe faible"),
    ("PAM : blocage", "aucun blocage du compte après des échecs répétés"),
    ("AppArmor", "profil AppArmor désactivé"),
    ("sshd", "connexion directe en root autorisée par SSH"),
    ("pare-feu", "aucune configuration de pare-feu"),
    ("secret en clair", "identifiant passé à curl"),
    ("clé sans phrase", "clé privée SSH SANS phrase de passe"),
    ("partage : fichiers", "fichiers appartenant à un autre compte dans le dossier personnel"),
    ("partage : su", "prise de l'identité d'un autre compte local (su)"),
    ("partage : historique",
     "prise de l'identité d'un autre compte local depuis l'interpréteur"),
    ("partage : clé commune", "la même clé SSH ouvre plusieurs comptes"),
    ("support amovible", "support amovible monté"),
    ("règle : domaine", "domaine présent dans une base de navigateur"),
    ("règle : fichier", "fichier présent dans le dossier personnel"),
    ("règle : commande", "commande saisie dans l'interpréteur"),
    ("règle : wifi", "réseau sans fil enregistré sur le poste"),
]


# Un libellé ne suffit pas toujours. « domaine présent dans une base de
# navigateur » sort aussi bien de l'historique que d'un cookie ; or le cookie
# et le mot de passe enregistré sont les deux pièces qui survivent au vidage de
# l'historique, et ce sont celles qu'une extraction d'hôtes rate le plus
# facilement (un domaine de cookie s'écrit « .netflix.com », avec un point de
# tête). Ces attendus-là se vérifient donc sur le contenu du constat.
ATTENDUS_PRECIS = [
    ("règle : cookie", "constat", {"constat": "domaine présent dans une base de navigateur",
                                   "source": "cookies.sqlite", "regle": "R1"}),
    ("règle : mot de passe enregistré",
     "constat", {"constat": "domaine présent dans une base de navigateur",
                 "source": "logins.json"}),
    ("règle : marque-page", "constat", {"constat": "domaine présent dans une base de navigateur",
                                        "source": "Bookmarks"}),
]

# Une chaîne qui n'existe QUE dans les chaînes brutes du périphérique. Si
# l'extracteur cesse de les parcourir, elle sort « ABSENTE » et le test tombe —
# et comme le libellé du fait est désormais le même pour tous les fichiers,
# c'est la SOURCE qui doit être vérifiée, pas l'intitulé.
# Le regroupement des supports doit rendre le vid:pid ET le numéro de série
# rattaché par le temps : c'est tout l'intérêt du tableau, et c'est le
# rapprochement le plus fragile du lot.
#
# Une SEULE liste : trois listes séparées recollées à la main dans la boucle
# d'en bas voulaient dire qu'une quatrième serait écrite et jamais lue.
ATTENDUS_CHAMPS = [
    ("support : vid:pid + série", {"fait": "support amovible reconnu",
                                   "valeur": "4C530001230405112233",
                                   "vid": "0781", "pid": "5583",
                                   "montages": "/run/media/jdupont/SANDISK32",
                                   "acteur": "jdupont"}),

    # L'outil doit regarder DANS les chaînes du disque et DANS ce que photorec
    # a rendu — deux endroits où rien d'autre dans le rapport ne va. Les appâts
    # n'existent qu'à ces endroits-là.
    ("intérêt : photorec lisible", {"fait": "repéré dans les octets d'un fichier",
                                    "valeur": "clé privée",
                                    "source": "PHOTOREC/recup_1/f0002.txt"}),
    ("intérêt : photorec mot de passe", {"valeur": "mot de passe en clair",
                                         "source": "PHOTOREC/recup_1/f0007.txt"}),
    ("intérêt : chaînes du disque", {"valeur": "jeton AWS",
                                     "source": "_strings_racine.txt"}),
    ("intérêt : docx décompressé", {"valeur": "mot de passe en clair",
                                    "source": "PHOTOREC/recup_1/f0008.docx"}),
    # Le document doit être CARACTÉRISÉ, pas seulement fouillé : son sujet lu
    # dans le XML du .docx, et ce qu'il porte. « porte » ne dit QUE le contenu
    # (utilisateur, système) : les motifs sensibles sont des faits « intérêt »
    # sur la même source, et c'est là-dessus que le rapport recolle les deux.
    # Les chercher aussi ici, c'était un second moteur qui se contredisait.
    ("document : sujet du docx", {"fait": "fichier rendu sans nom, et lisible",
                                  "valeur": "Compte rendu",
                                  "source": "PHOTOREC/recup_1/f0008.docx",
                                  "porte": "utilisateur"}),
    ("document : remplissage écarté", {"fait": "fichier rendu sans nom, et lisible",
                                       "source": "f0007.txt"}),
    ("document : xfs_undelete", {"fait": "fichier rendu sans nom, et lisible",
                                 "source": "SUPPRIMES/racine/",
                                 "porte": "utilisateur"}),

    ("chaîne imbriquée dans un motif", {"fait": "texte recherché présent dans un fichier",
                                        "valeur": "Bienvenue2025!",
                                        "source": "PHOTOREC/recup_1/f0007.txt"}),
    ("indicateur dans les chaînes", {"fait": "texte recherché présent dans un fichier",
                                     "valeur": "chaine-effacee-que-rien-d-autre-ne-porte",
                                     "source": "STRINGS/"}),
    ("indicateur dans un .gz du tar", {"fait": "texte recherché présent dans un fichier",
                                       "valeur": "journal-tourne-et-comprime-dans-le-tar",
                                       "source": "_var_log.tar.gz → var/log/auth.log.2.gz"}),

    # Un seul moteur de motifs : le fait « document » ne porte plus de champ
    # « interet ». S'il en reparaissait un, c'est qu'une seconde recherche a
    # été rajoutée dans documents(), et les deux se contrediraient.
    ("un seul moteur de motifs", {"__absent__": "interet"}),

    # ── la synthèse des adresses ──────────────────────────────────────
    # Ce qui compte n'est pas de trouver l'adresse, c'est de dire D'OÙ elle
    # sort. La même IP vue dans un profil réseau ET dans les octets du disque
    # doit porter les deux provenances sur une SEULE ligne.
    ("adresse : deux provenances", {"fait": "adresse IP vue dans la collecte",
                                    "valeur": "10.0.0.9",
                                    "ou": "chaînes du disque / configuration réseau",
                                    "portee": "privée"}),
    # Vue seulement dans les octets bruts : jamais mieux qu'« à vérifier »,
    # quelle que soit la catégorie du fait qui la porte. C'est le DOSSIER qui
    # décide de la provenance, pas l'intitulé.
    ("adresse : sans provenance", {"valeur": "192.168.0.5", "genre": "IP",
                                   "confiance": "à vérifier",
                                   "ou": "chaînes du disque"}),
    # Le bit « administré localement » : une MAC tirée au hasard ne suit pas une
    # machine d'un réseau à l'autre. Le rapport doit le dire, sinon on croit
    # identifier un matériel alors qu'on suit un tirage.
    ("adresse : MAC tirée au hasard", {"valeur": "b2:7a:11:c0:ff:ee",
                                       "portee": "administrée localement"}),
    ("adresse : MAC constructeur", {"valeur": "dc:a6:32:1b:4e:07",
                                    "portee": "constructeur DC:A6:32"}),
    # Une MAC écrite dans les octets du disque et nulle part ailleurs : la seule
    # pièce qui garde la trace d'un point d'accès ou d'une machine du réseau
    # local dont plus aucune configuration ne parle.
    ("adresse : MAC des octets bruts", {"valeur": "e8:9c:25:3f:0a:b1",
                                        "genre": "MAC", "confiance": "à vérifier"}),
    # Les URL sont regroupées par HÔTE, sinon ce n'est plus une synthèse. Il
    # n'existe qu'UN fait « adresse » par (genre, valeur) : deux attentes qui
    # trouvent chacune une provenance différente pour le même hôte prouvent
    # donc qu'elles ont été recollées sur une seule ligne. Les nommer une par
    # une, plutôt que d'exiger la chaîne jointe entière, évite qu'un simple
    # changement d'ordre fasse tomber un test qui ne porte pas là-dessus.
    ("adresse : URL groupée par hôte", {"valeur": "www.yggtorrent.wtf",
                                        "genre": "URL", "ou": "navigation"}),
    ("adresse : le même hôte, du disque", {"valeur": "www.yggtorrent.wtf",
                                           "genre": "URL",
                                           "ou": "chaînes du disque"}),

    # 203.0.113.42 est l'indicateur que le piège dit « jamais vue ici ». Son
    # fait d'ABSENCE porte la valeur cherchée : lue comme une adresse, elle
    # rangeait parmi les adresses VUES sur le poste celle que l'analyste avait
    # justement cherchée SANS la trouver. Le pire contresens possible ici.
    ("adresse : une absence n'est pas une adresse",
     {"__jamais__": {"categorie": "adresse", "valeur": "203.0.113.42"}}),
    # Le contexte d'un motif est coupé à soixante octets sans égard pour ce
    # qu'il tranche : « …/999 https://www.yggtor » y rend un hôte qui n'a
    # jamais existé. Inventer une adresse est plus grave que d'en manquer une.
    ("adresse : pas d'hôte tronqué",
     {"__jamais__": {"categorie": "adresse", "valeur": "www.yggtor"}}),

    # La polarité doit être DITE, des deux côtés. Un fait « indicateur » qui
    # n'a pas de « trouve » est un fait dont seule la phrase française dit
    # s'il rapporte une présence ou une absence — et c'est ainsi que la valeur
    # d'une absence se glisse là où on lit des trouvailles.
    ("indicateur : la polarité est dite",
     {"__jamais__": {"categorie": "indicateur", "trouve": None}}),

    # ── l'historique de navigation n'est pas borné ────────────────────
    # Le piège pose 22 pages dans places.sqlite — dont 20 anciennes — et 1 dans
    # Chrome. Les 23 doivent devenir des faits : une borne garde « les plus
    # récentes d'abord » et laisse dehors les anciennes, qui sont justement
    # celles qu'aucune autre pièce ne porte quand l'historique récent a été
    # vidé. Compter est la SEULE forme qui attrape ça — une recherche par
    # présence trouve toujours les premières lignes et ne voit rien.
    ("navigation : rien n'est borné", {"__compte__": ("page visitée", 23)}),
    ("navigation : la plus ancienne est là", {"fait": "page visitée",
                                              "valeur": "vieux-site-003.example"}),
    # Et si quelqu'un rebornait la lecture selon l'idiome de la maison, il
    # poserait l'un de ces deux faits pour le dire. Qu'ils n'existent jamais
    # est la garde qui tient même sur un piège plus petit que la borne.
    ("navigation : aucun fait de borne",
     {"__jamais__": {"categorie": "limite", "fait": "historique de navigation tronqué"}}),
    ("navigation : aucune borne de lecture",
     {"__jamais__": {"categorie": "limite",
                     "fait": "marque-pages : la borne de lecture est atteinte"}}),
]


# Ce que Crush REFUSE, repris de Skill.Validate (internal/skills/skills.go).
# Tout est compté en OCTETS : ce sont des len() sur des chaînes Go, et en
# français chaque accent en pèse deux. Un skill que Crush refuse disparaît de
# l'agent avec une simple pastille rouge — d'où l'intérêt de le voir ici.
NOM_MAX, DESCRIPTION_MAX, COMPATIBILITE_MAX = 64, 1024, 500
RE_NOM_SKILL = re.compile(r'^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$')

# Le corps, lui, n'est PAS borné par Crush : c'est une convention du projet,
# tirée de la spécification Agent Skills. Elle compte quand même, parce que le
# corps entier entre dans le contexte du modèle à chaque activation.
CORPS_MAX_JETONS = 5000
CORPS_MAX_LIGNES = 500


def frontmatter_sain(racine):
    """Le frontmatter d'un SKILL.md doit survivre à un vrai analyseur YAML.

    Crush le passe à gopkg.in/yaml.v3 : un « : » suivi d'une espace dans un
    scalaire NON QUOTÉ ouvre une association, et le fichier est rejeté avec
    « mapping values are not allowed in this context ». Le skill disparaît
    alors de l'agent, et l'interface se contente d'une pastille rouge — c'est
    exactement comme ça qu'une description bien écrite peut tout casser.
    Vérifier « la clé existe » avec une expression rationnelle ne voit rien de
    tout ça : il faut regarder ce qui rend le scalaire invalide.
    """
    ennuis = []
    for nom in sorted(os.listdir(racine)):
        chemin = os.path.join(racine, nom, "SKILL.md")
        if not os.path.isfile(chemin):
            continue
        texte = open(chemin, encoding="utf-8").read()
        if not texte.startswith("---\n") or "\n---" not in texte[4:]:
            ennuis.append((chemin, "frontmatter absent ou non refermé"))
            continue
        # Le CORPS est lu à chaque activation du skill, en entier, et il est
        # pris sur le contexte du modèle. La borne est celle de la spécification
        # Agent Skills, et le README annonce qu'elle est vérifiée ICI : sans ce
        # contrôle, elle se franchit d'un paragraphe à la fois sans que rien ne
        # le dise. Ce qui déborde va dans references/, lu à la demande.
        # En OCTETS, comme Crush : son ApproxTokenCount fait (len(s)+3)/4 sur
        # une chaîne Go, où len() compte les octets. En français, chaque accent
        # en pèse deux — compter les caractères sous-estime d'un bon 3 %, et
        # c'est ainsi qu'un corps déjà au-dessus de la borne passait pour bon.
        corps = texte[4:].split("\n---", 1)[1].strip()
        jetons = (len(corps.encode("utf-8")) + 3) // 4
        if jetons > CORPS_MAX_JETONS:
            ennuis.append((chemin, f"corps de ~{jetons} jetons : au-dessus des "
                                   f"{CORPS_MAX_JETONS} de la spécification. "
                                   f"Déplacez un passage dans references/"))
        if corps.count("\n") > CORPS_MAX_LIGNES:
            ennuis.append((chemin, f"corps de {corps.count(chr(10))} lignes : "
                                   f"au-dessus des {CORPS_MAX_LIGNES}"))
        # Les quatre refus de Crush. Les vérifier ICI et pas seulement « le
        # frontmatter s'analyse » : un scalaire valide mais trop long, ou un
        # nom qui ne colle pas au dossier, passait pour bon et faisait
        # disparaître le skill.
        entete = {}
        for ligne in texte[4:].split("\n---", 1)[0].splitlines():
            cle, _, valeur = ligne.partition(":")
            if valeur and cle == cle.strip() and cle.strip():
                entete[cle.strip()] = valeur.strip().strip("\"'")
        if not entete.get("description"):
            ennuis.append((chemin, "« description » absente — Crush refuse le skill"))
        for cle, borne in (("name", NOM_MAX), ("description", DESCRIPTION_MAX),
                           ("compatibility", COMPATIBILITE_MAX)):
            taille = len(entete.get(cle, "").encode("utf-8"))
            if taille > borne:
                ennuis.append((chemin, f"« {cle} » fait {taille} octets, Crush "
                                       f"refuse au-delà de {borne}"))
        if not RE_NOM_SKILL.match(entete.get("name", "")):
            ennuis.append((chemin, f"« name » = {entete.get('name')!r} : Crush "
                                   "attend des lettres, des chiffres et des "
                                   "traits d'union simples"))
        elif entete["name"].lower() != nom.lower():
            ennuis.append((chemin, f"« name » = {entete['name']!r} mais le "
                                   f"dossier est {nom!r} — Crush exige l'égalité"))

        for ligne in texte[4:].split("\n---", 1)[0].splitlines():
            if not ligne.strip() or ligne.lstrip().startswith("#"):
                continue
            if ":" not in ligne:
                continue
            cle, _, valeur = ligne.partition(":")
            if not cle.strip() or cle != cle.strip():
                continue
            valeur = valeur.strip()
            if not valeur or valeur[0] in "\"'|>[{&*!":     # quoté ou structuré
                continue
            if ": " in valeur or valeur.endswith(":"):
                ennuis.append((chemin, f"« {cle} » : « : » dans un scalaire non "
                                       f"quoté — mettez la valeur entre guillemets"))
            elif " #" in valeur:
                ennuis.append((chemin, f"« {cle} » : « #» ouvre un commentaire "
                                       f"dans un scalaire non quoté"))
    return ennuis


def lire(chemin, cle):
    with open(chemin, encoding="utf-8") as fh:
        return {json.loads(l)[cle] for l in fh if l.strip()}


def blocs_bornes():
    """Un .gz rend des blocs BORNÉS, et le plafond d'archive joue sur lui.

    Un journal tourné se comprime d'un facteur trois cents : rendu d'un seul
    tenant, un bloc d'entrée d'un mégaoctet en faisait deux cents en mémoire,
    que le chercheur recopiait puis balayait une fois par motif — l'extraction
    paraissait bloquée. Et le plafond, la garde contre les bombes de
    décompression, ne couvrait pas la forme comprimée la PLUS courante.

    Le piège synthétique est trop petit pour montrer ça : ce contrôle-ci
    fabrique donc ses propres octets, et il vérifie les trois propriétés qui
    doivent tenir ensemble — bornées, complètes, et l'empreinte du fichier
    entier malgré la troncature.
    """
    import gzip, hashlib, io
    sys.path.insert(0, os.path.join(SKILLS, "forensic-linux", "scripts"))
    import extraire

    ligne = b"Jan  8 14:02:11 pc01 systemd[1]: Started Session 4231 of jdupont.\n"
    clair = ligne * (24 * 1024 * 1024 // len(ligne))
    comp = gzip.compress(clair, 6)
    etat, rendu, gros = {}, 0, 0
    for _, c in extraire._blocs("syslog.2.gz", lambda: io.BytesIO(comp), etat):
        rendu += len(c)
        gros = max(gros, len(c))
    yield ("gz : blocs bornés", gros <= (1 << 20),
           f"plus gros bloc clair {gros / 1048576:.2f} Mo (max 1,00)")
    yield ("gz : rien n'est perdu", rendu == len(clair),
           f"{rendu} octets rendus sur {len(clair)}")

    # Au-delà du plafond : on s'arrête, on le DIT, et l'empreinte reste celle
    # du fichier entier — sans quoi une empreinte recherchée ne correspondrait
    # plus à rien, en silence.
    bombe = gzip.compress(b"A" * (extraire.PLAFOND_ARCHIVE + (8 << 20)), 6)
    etat, h, rendu = {}, hashlib.sha256(), 0
    for b, c in extraire._blocs("bombe.gz", lambda: io.BytesIO(bombe), etat):
        h.update(b)
        rendu += len(c)
    yield ("gz : le plafond joue", "tronque" in etat and rendu <= extraire.PLAFOND_ARCHIVE + (1 << 20),
           f"{rendu / 1048576:.0f} Mo rendus, etat={etat.get('tronque') or 'AUCUN'}")
    yield ("gz : empreinte complète", h.hexdigest() == hashlib.sha256(comp := bombe).hexdigest(),
           "sha256 du fichier entier malgré la troncature")


def main():
    base = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "artefacts")
    shutil.rmtree(base, ignore_errors=True)
    os.makedirs(base)
    R = batir(base)
    regles = os.path.join(SKILLS, "conformite-linux", "references", "regles",
                          "usage-non-professionnel.regles")
    faits = os.path.join(base, "faits.jsonl")
    constats = os.path.join(base, "constats.jsonl")
    subprocess.run([sys.executable, os.path.join(SKILLS, "forensic-linux", "scripts", "extraire.py"),
                    R, "-o", faits, "--indicateurs", os.path.join(base, "indicateurs.txt")],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, os.path.join(SKILLS, "conformite-linux", "scripts", "controles.py"),
                    R, "--regles", regles, "--faits", faits, "-o", constats],
                   check=True, stdout=subprocess.DEVNULL)
    for script, entree, sortie in (
            ("forensic-linux", faits, os.path.join(base, "rapport-forensic.md")),
            ("conformite-linux", constats, os.path.join(base, "rapport-conformite.md"))):
        cmd = [sys.executable, os.path.join(SKILLS, script, "scripts", "brouillon.py"),
               entree, "-o", sortie]
        if script == "conformite-linux":
            cmd += ["--faits", faits]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    manques = 0
    for titre, fichier, cle, attendus in (
            ("FAITS", faits, "fait", ATTENDUS_FAITS),
            ("CONSTATS", constats, "constat", ATTENDUS_CONSTATS)):
        vus = lire(fichier, cle)
        print(f"\n── {titre} ({len(vus)} libellés distincts) ──")
        for artefact, attendu in attendus:
            ok = attendu in vus
            manques += not ok
            print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:28s} {attendu}")
    # Un plantage à la fin d'un parcours de plusieurs heures ne doit pas coûter
    # les heures. On coupe donc le journal en plein milieu d'une ligne — ce que
    # fait un plantage réel — et on exige que la reprise rende EXACTEMENT le
    # même fichier de faits qu'un passage d'un seul tenant. Sans cette
    # égalité, la reprise ne serait pas une reprise : ce serait une autre
    # analyse, avec d'autres identifiants.
    print("\n── DÉCOMPRESSION BORNÉE ──")
    for artefact, ok, detail in blocs_bornes():
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:28s} {detail}")

    print("\n── REPRISE APRÈS PLANTAGE ──")
    journal = os.path.splitext(faits)[0] + "-reprise.jsonl"
    complet = open(faits, encoding="utf-8").read()
    lignes = open(journal, encoding="utf-8").read().splitlines(keepends=True)
    with open(journal, "w", encoding="utf-8") as fh:
        fh.writelines(lignes[:max(1, len(lignes) // 2)])
        fh.write('{"chemin": "coupé par le plant')      # ligne tronquée
    repris = os.path.join(base, "faits-repris.jsonl")
    subprocess.run([sys.executable, os.path.join(SKILLS, "forensic-linux", "scripts", "extraire.py"),
                    R, "-o", repris, "--indicateurs", os.path.join(base, "indicateurs.txt")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pareil = open(repris, encoding="utf-8").read() == complet
    manques += not pareil
    print(f"  {'ok ' if pareil else 'MANQUE'}  {'journal coupé, faits rejoués':28s} "
          f"identiques à un passage d'un seul tenant")

    # Une reprise RÉUSSIE ne doit pas se détruire elle-même. Le journal est
    # rouvert en écriture à chaque passage : ce qu'on n'y recopie pas est
    # perdu. Le premier plantage était couvert, le SECOND ne l'était plus —
    # et c'est justement le cas où l'on reprend deux fois.
    jr = os.path.splitext(repris)[0] + "-reprise.jsonl"
    avant = sum(1 for _ in open(jr, encoding="utf-8"))
    man = os.path.splitext(repris)[0] + "-manifeste.json"
    pieces = len(json.load(open(man, encoding="utf-8"))["pieces_lues"])
    subprocess.run([sys.executable, os.path.join(SKILLS, "forensic-linux", "scripts", "extraire.py"),
                    R, "-o", repris, "--indicateurs", os.path.join(base, "indicateurs.txt")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    apres = sum(1 for _ in open(jr, encoding="utf-8"))
    ok = apres == avant and avant > 1
    manques += not ok
    print(f"  {'ok ' if ok else 'MANQUE'}  {'le journal survit à la reprise':28s} "
          f"{apres} ligne(s), {avant} avant")
    # Et la preuve « quels octets ont été analysés » doit rester ENTIÈRE : une
    # pièce rejouée a bien été analysée, même si elle ne l'a pas été à ce
    # passage-ci. Sans cela le manifeste prétendait, en silence, qu'elle ne
    # l'avait pas été.
    apres_p = len(json.load(open(man, encoding="utf-8"))["pieces_lues"])
    ok = apres_p == pieces and pieces > 1
    manques += not ok
    print(f"  {'ok ' if ok else 'MANQUE'}  {'manifeste entier après reprise':28s} "
          f"{apres_p} pièces, {pieces} avant")

    print("\n── SYNTHÈSES : LES CHAMPS, PAS SEULEMENT LE LIBELLÉ ──")
    with open(faits, encoding="utf-8") as fh:
        lus_f = [json.loads(l) for l in fh if l.strip()]
    for artefact, exige in ATTENDUS_CHAMPS:
        # « __absent__ » : aucun fait ne doit porter ce champ. C'est l'inverse
        # du reste, et c'est ce qui permet de tester qu'un mécanisme a bien
        # DISPARU — un test qui ne sait dire que « présent » laisse revenir en
        # silence ce qu'on vient de retirer.
        interdit = exige.get("__absent__")
        # « __jamais__ » : un dict {champ: valeur} qu'AUCUN fait ne doit porter
        # en entier. C'est ainsi qu'on teste qu'une chose vraie ailleurs ne
        # s'est pas glissée là où elle serait un contresens. La comparaison est
        # EXACTE, à rebours du reste : « www.yggtor » est un morceau du
        # légitime « www.yggtorrent.wtf », et une recherche par sous-chaîne
        # sonnerait l'alarme sur le fait même qu'elle doit laisser passer.
        # « __compte__ » : (libellé de fait, nombre) — il doit y en avoir
        # EXACTEMENT autant. C'est la seule forme qui attrape une troncature :
        # une borne laisse toujours passer les premières lignes, donc une
        # recherche par présence trouve ce qu'elle cherche et ne voit rien.
        compte = exige.get("__compte__")
        jamais = exige.get("__jamais__")
        if compte:
            quoi, attendu = compte
            vu = sum(1 for d in lus_f if d.get("fait") == quoi)
            ok = vu == attendu
            etiquette = f"{vu} « {quoi} » (attendu {attendu})"
        elif jamais:
            ok = not any(all(d.get(k) == v for k, v in jamais.items())
                         for d in lus_f)
            etiquette = " + ".join(f"{k}={v}" for k, v in jamais.items())
        elif interdit:
            ok = not any(interdit in d for d in lus_f)
            etiquette = interdit
        else:
            ok = any(all(v in str(d.get(k, "")) for k, v in exige.items()) for d in lus_f)
            etiquette = exige.get("valeur") or exige.get("source")
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:28s} {etiquette}")

    print(f"\n── PIÈCES QUI SURVIVENT AU VIDAGE DE L'HISTORIQUE ──")
    with open(constats, encoding="utf-8") as fh:
        lus = [json.loads(l) for l in fh if l.strip()]
    for artefact, _cle, exige in ATTENDUS_PRECIS:
        ok = any(all(v in str(d.get(k, "")) for k, v in exige.items()) for d in lus)
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:28s} {exige['source']}")

    racine = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("\n── FRONTMATTER DES SKILL.md ──")
    ennuis = frontmatter_sain(racine)
    for chemin, motif in ennuis:
        print(f"  MANQUE  {os.path.basename(os.path.dirname(chemin)):<20} {motif}")
    manques += len(ennuis)
    if not ennuis:
        print("  ok      les frontmatter passent un analyseur YAML")

    print(f"\n{base}")
    if manques:
        print(f"{manques} artefact(s) collecté(s) mais sans effet — voir ci-dessus.",
              file=sys.stderr)
    return 1 if manques else 0


if __name__ == "__main__":
    sys.exit(main())
