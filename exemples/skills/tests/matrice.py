# -*- coding: utf-8 -*-
"""Cinq collectes synthétiques, une par famille de distribution, telles que
collecte-linux.conf les produirait : les pièces propres à chaque famille sont
là, celles qui n'existent pas sur cette famille n'y sont pas.

    python3 tests/matrice.py <dossier de sortie>

puis, sur chacune : extraire.py, controles.py --regles --faits, les deux
brouillon.py. Ce que chaque famille doit donner est écrit en tête de son bloc.
Une pièce nouvelle dans collecte-linux.conf se reflète ici, ou elle n'est pas
testée.
"""
import calendar, gzip, io, json, os, shutil, sqlite3, sys, tarfile, tempfile, time

# le struct utmp est celui de l'extracteur : un test qui en redéclarerait un
# certifierait une lecture fausse avec une écriture fausse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "forensic-linux", "scripts"))
from extraire import UTMP                                              # noqa: E402
assert UTMP.size == 384

def epoch(iso): return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%S"))
def tarz(chemin, membres):
    with tarfile.open(chemin, "w:gz") as t:
        for nom, blob in membres.items():
            if isinstance(blob, str): blob = blob.encode("utf-8")
            i = tarfile.TarInfo("./" + nom); i.size = len(blob); i.mtime = epoch("2026-01-08T12:00:00")
            t.addfile(i, io.BytesIO(blob))
def sqlite_blob(schema, rows):
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as t: nom = t.name
    cx = sqlite3.connect(nom)
    for sql in schema: cx.execute(sql)
    for sql, r in rows: cx.executemany(sql, r)
    cx.commit(); cx.close(); b = open(nom, "rb").read(); os.unlink(nom); return b
def utmp(entries):
    out = b""
    for typ, pid, tty, user, host, iso in entries:
        out += UTMP.pack(typ, pid, tty.encode().ljust(32, b"\0"), tty[-4:].encode().ljust(4, b"\0"),
                      user.encode().ljust(32, b"\0"), host.encode().ljust(256, b"\0"), 0, 0, 0, epoch(iso), 0, b"\0"*16, b"\0"*20)
    return out

def wtmpdb(rows):
    """wtmp.db de wtmpdb : Login et Logout en MICROsecondes — c'est la règle
    que l'extracteur doit connaître, et ce fichier est ce qui la vérifie."""
    return sqlite_blob(
        ["CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT, Login INTEGER, "
         "Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)"],
        [("INSERT INTO wtmp VALUES(?,?,?,?,?,?,?,?)",
          [(i + 1, 2, user, epoch(login) * 1000000, epoch(logout) * 1000000 if logout else None,
            tty, host, service) for i, (user, login, logout, tty, host, service) in enumerate(rows)])])


B = None


def base(P, osrel, tz="Europe/Paris"):
    R = os.path.join(B, P)
    for d in ("SYSTEME", "COMPTES", "PAQUETS", "RESEAU", "JOURNAUX", "CONNEXIONS", "PERSISTANCE", "TIMELINE"):
        os.makedirs(os.path.join(R, d))
    w = lambda rel, c: io.open(os.path.join(R, rel), "wb").write(c.encode("utf-8") if isinstance(c, str) else c)
    T = lambda rel, membres: tarz(os.path.join(R, rel), membres)
    w("SYSTEME/hostname", P.lower() + "\n"); w("SYSTEME/os-release", osrel); w(f"SYSTEME/{P}_localtime.txt", tz + "\n")
    w(f"COMPTES/{P}_passwd.txt", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\n")
    T(f"COMPTES/{P}_droits.tar.gz", {"etc/shadow": "root:$6$a$b:19000:0:99999:7:::\nalice:$6$c$d:19800:0:90:7:::\n"})
    T(f"COMPTES/{P}_alice_artefacts.tar.gz", {".bash_history": "ls\n#1767700000\nsudo -u bob true\n", ".config/chromium/Default/History": sqlite_blob(
        ["CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)",
         "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)",
         "CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, start_time INTEGER)"],
        [("INSERT INTO urls VALUES(?,?,?,?,?)", [(1, "https://www.youtube.com/w", "yt", 2, (epoch("2026-01-06T12:00:00") + 11644473600) * 1000000)])])})
    w(f"COMPTES/{P}_alice_inventaire.txt", "/mnt/i/home/alice:\ntotal 8\ndrwxr-xr-x 2 alice alice 4096 janv.  6 12:00 .\n-rw-r--r-- 1 alice alice   10 janv.  6 12:00 film.mkv\n")
    T(f"PERSISTANCE/{P}_persistance.tar.gz", {"etc/crontab": "0 3 * * * root /usr/bin/updatedb\n"})
    return R, w, T

def main():
    global B
    B = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "matrice")
    shutil.rmtree(B, ignore_errors=True)
    # ── Fedora 40 : rpm --last en français, dnf5, wtmp.db (microsecondes) + lastlog2.db,
    #    journal systemd seul (pas de rsyslog). Attendu : 2 sessions, la pose du système
    #    datée par rpm, la commande dnf datée par la base dnf5, une session un samedi (R6).
    P = "PC01_A1_MAT_fedora"; R, w, T = base(P, 'ID=fedora\nVERSION_ID=40\nPRETTY_NAME="Fedora Linux 40 (Workstation Edition)"\n')
    w(f"PAQUETS/{P}_paquets.txt", "kodi-21.0-1.fc40.x86_64                   ven. 03 janv. 2026 10:22:31\nfirefox-134.0-1.fc40.x86_64               jeu. 02 janv. 2026 09:00:00\nfilesystem-3.18-8.fc40.x86_64             mar. 03 sept. 2024 14:00:00\n")
    dnf5 = sqlite_blob(["CREATE TABLE trans(id INTEGER PRIMARY KEY, dt_start INTEGER, dt_end INTEGER, cmdline TEXT)"],
                       [("INSERT INTO trans VALUES(?,?,?,?)", [(1, epoch("2026-01-03T09:22:31"), epoch("2026-01-03T09:22:40"), "dnf install kodi")])])
    T(f"PAQUETS/{P}_historique.tar.gz", {"usr/lib/sysimage/libdnf5/transaction_history.sqlite": dnf5, "var/log/dnf5.log": "2026-01-03T09:22:31+0000 INFO Installed: kodi\n"})
    wdb = wtmpdb([("alice", "2026-01-06T08:05:00", "2026-01-06T17:10:00", "tty2", "", "gdm"),
                  ("alice", "2026-01-10T14:00:00", None, "pts/0", "10.0.0.9", "sshd")])
    ll2 = sqlite_blob(["CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, PamService TEXT)"],
                      [("INSERT INTO Lastlog2 VALUES(?,?,?,?,?)", [("alice", epoch("2026-01-10T14:00:00"), "pts/0", "10.0.0.9", "sshd")])])
    w("CONNEXIONS/wtmp.db", wdb); w("CONNEXIONS/lastlog2.db", ll2)
    w(f"JOURNAUX/{P}_journal.txt", "2026-01-06T09:15:03+0100 pc01 sudo[4242]: alice : TTY=tty2 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/dnf install kodi\n2026-01-06T10:00:00+0100 pc01 kernel: usb 1-1: New USB device found, idVendor=0781, idProduct=5583\n")
    T(f"JOURNAUX/{P}_var_log.tar.gz", {"var/log/dnf.log": "x\n"})
    T(f"RESEAU/{P}_reseau.tar.gz", {"etc/NetworkManager/system-connections/Maison.nmconnection": "[connection]\nid=Maison\nuuid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\ntype=wifi\n\n[wifi]\nssid=Livebox-Maison\n",
                                                       "var/lib/NetworkManager/timestamps": "[timestamps]\naaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa=1767800000\n", "etc/ssh/sshd_config": "PermitRootLogin no\n", "etc/firewalld/firewalld.conf": "DefaultZone=public\n"})

    # ── Debian 13 : dpkg, apt history (dont un .gz), wtmp.db, wpa_supplicant, auth.log
    #    sans année. Attendu : la pose datée par dpkg.log, un su vers bob (partage), le
    #    McDonald's dans wpa_supplicant (R6), l'USB du syslog tourné avec l'année déduite.
    P = "PC02_A1_MAT_debian"; R, w, T = base(P, 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n')
    w(f"PAQUETS/{P}_paquets.txt", "Souhait=inconnU/Installé\n||/ Nom Version Architecture Description\n+++-===\nii  transmission-gtk  4.0.6-1  amd64  torrent\nii  firefox-esr 128.0 amd64 nav\n")
    T(f"PAQUETS/{P}_historique.tar.gz", {"var/log/dpkg.log": "2025-06-01 08:00:00 install base-files:amd64 <none> 13.1\n2026-01-04 18:30:00 install transmission-gtk:amd64 <none> 4.0.6-1\n",
                                                              "var/log/apt/history.log": "Start-Date: 2026-01-04  18:29:58\nCommandline: apt install transmission-gtk\nInstall: transmission-gtk:amd64 (4.0.6-1)\nEnd-Date: 2026-01-04  18:30:05\n",
                                                              "var/log/apt/history.log.1.gz": gzip.compress(b"Start-Date: 2025-12-01  10:00:00\nCommandline: apt remove kodi\nRemove: kodi:amd64 (20.5)\nEnd-Date: 2025-12-01  10:00:04\n")})
    w("CONNEXIONS/wtmp.db", wtmpdb([("alice", "2026-01-04T17:50:00", "2026-01-04T19:00:00", "tty2", "", "login")]))
    T(f"JOURNAUX/{P}_var_log.tar.gz", {"var/log/auth.log": "Jan  4 18:29:50 pc02 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install transmission-gtk\nJan  4 18:40:00 pc02 su: (to bob) alice on pts/1\nJan  4 18:40:00 pc02 su: pam_unix(su:session): session opened for user bob(uid=1001) by alice(uid=1000)\n",
                                                            "var/log/syslog.1.gz": gzip.compress(b"Dec 30 08:00:00 pc02 kernel: usb 2-1: New USB device found, idVendor=0951, idProduct=1666\nDec 30 08:00:00 pc02 kernel: usb 2-1: SerialNumber: 0019E06B0001\n")})
    T(f"RESEAU/{P}_reseau.tar.gz", {"etc/wpa_supplicant/wpa_supplicant.conf": 'ctrl_interface=/run/wpa_supplicant\nnetwork={\n    ssid="McDonalds Free WiFi"\n    key_mgmt=NONE\n}\nnetwork={\n    ssid="Bureau-5G"\n    psk="secret"\n}\n',
                                                       "etc/network/interfaces": "auto eth0\niface eth0 inet dhcp\n", "etc/ssh/sshd_config": "PasswordAuthentication yes\n", "etc/nftables.conf": "table inet filter {}\n"})

    # ── openSUSE : zypp history (commandes en « # »), rpm --last vide (base ndb), wtmp
    #    binaire, NM avec un profil réservé à alice. Attendu : une limite « liste vide »,
    #    la pose et steam datés par zypp, SNCF_WIFI imputé à alice (R6), 2 sessions.
    P = "PC03_A1_MAT_opensuse"; R, w, T = base(P, 'ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\nVERSION_ID="20260105"\nPRETTY_NAME="openSUSE Tumbleweed"\n')
    w(f"PAQUETS/{P}_paquets.txt", "")
    T(f"PAQUETS/{P}_historique.tar.gz", {"var/log/zypp/history": "# 2025-03-01 10:00:00|command|root@pc03|'zypper' 'in' 'patterns-base'|\n2025-03-01 10:00:05|install|filesystem|84.87-1.1|x86_64|root@pc03|repo-oss|abc|\n# 2026-01-05 21:10:00|command|alice@pc03|'zypper' 'in' 'steam'|\n2026-01-05 21:10:30|install|steam|1.0.0.79-1.1|x86_64|alice@pc03|non-oss|def|\n2026-01-07 09:00:00|remove|kodi|21.0-1.1|x86_64|root@pc03|\n"})
    w("CONNEXIONS/wtmp", utmp([(2, 0, "~", "reboot", "6.12", "2026-01-05T07:00:00"), (7, 500, "tty7", "alice", "", "2026-01-05T07:30:00"), (7, 600, "pts/2", "bob", "192.168.0.5", "2026-01-05T20:00:00"), (8, 500, "tty7", "", "", "2026-01-05T22:00:00")]))
    w(f"JOURNAUX/{P}_journal.txt", "2026-01-05T21:09:50+0100 pc03 sudo[77]: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/zypper in steam\n")
    T(f"RESEAU/{P}_reseau.tar.gz", {"etc/NetworkManager/system-connections/Gare.nmconnection": "[connection]\nid=Gare\nuuid=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\ntype=wifi\npermissions=user:alice:;\n\n[wifi]\nssid=SNCF_WIFI\n", "etc/ssh/sshd_config": "PermitRootLogin yes\n", "etc/firewalld/zones/public.xml": "<zone/>\n"})

    # ── Arch : pacman local (desc, %INSTALLDATE%) + pacman.log, iwd (dont un SSID en
    #    hexadécimal), wtmp binaire. Attendu : la pose datée par desc, lutris et qbittorrent
    #    posés (R2, R3), kodi retiré, « McDo Free WiFi. » décodé (R6).
    P = "PC04_A1_MAT_arch"; R, w, T = base(P, 'ID=arch\nPRETTY_NAME="Arch Linux"\n')
    w(f"PAQUETS/{P}_paquets.txt", "filesystem-2024.11.21-1\nlutris-0.5.18-1\nqbittorrent-5.0.3-1\n")
    T(f"PAQUETS/{P}_pacman_local.tar.gz", {"local/filesystem-2024.11.21-1/desc": "%%NAME%%\nfilesystem\n\n%%VERSION%%\n2024.11.21-1\n\n%%INSTALLDATE%%\n%d\n" % epoch("2024-12-01T10:00:00"),
                                                              "local/lutris-0.5.18-1/desc": "%%NAME%%\nlutris\n\n%%VERSION%%\n0.5.18-1\n\n%%INSTALLDATE%%\n%d\n" % epoch("2026-01-06T20:00:00"),
                                                              "local/qbittorrent-5.0.3-1/desc": "%%NAME%%\nqbittorrent\n\n%%VERSION%%\n5.0.3-1\n\n%%INSTALLDATE%%\n%d\n" % epoch("2026-01-06T20:05:00")})
    T(f"PAQUETS/{P}_historique.tar.gz", {"var/log/pacman.log": "[2024-12-01T10:00:00+0100] [PACMAN] Running 'pacman -S base'\n[2024-12-01T10:00:02+0100] [ALPM] installed filesystem (2024.11.21-1)\n[2026-01-06T20:00:00+0100] [PACMAN] Running 'pacman -S lutris qbittorrent'\n[2026-01-06T20:00:01+0100] [ALPM] installed lutris (0.5.18-1)\n[2026-01-06T20:05:00+0100] [ALPM] installed qbittorrent (5.0.3-1)\n[2026-01-07T08:00:00+0100] [ALPM] removed kodi (21.0-1)\n"})
    w("CONNEXIONS/wtmp", utmp([(7, 900, "tty1", "alice", "", "2026-01-06T19:50:00")]))
    w(f"JOURNAUX/{P}_journal.txt", "2026-01-06T19:59:58+0100 pc04 sudo[9]: alice : TTY=tty1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/pacman -S lutris qbittorrent\n")
    T(f"RESEAU/{P}_reseau.tar.gz", {"var/lib/iwd/Bureau-5G.psk": "[Security]\nPreSharedKey=abc\n", "var/lib/iwd/=4d63446f204672656520576946692e.psk": "[Security]\nPassphrase=x\n", "etc/ssh/sshd_config": "PermitRootLogin no\n", "etc/iptables/iptables.rules": "*filter\nCOMMIT\n"})

    # ── Alpine : apk, pas de wtmp ni de journal systemd (musl, OpenRC), messages de
    #    busybox, wpa_supplicant. Attendu : les limites wtmp et journal marquées « normal
    #    sur Alpine », le sudo et le SSH lus dans messages, transmission-cli (R3).
    P = "PC05_A1_MAT_alpine"; R, w, T = base(P, 'ID=alpine\nVERSION_ID=3.21.0\nPRETTY_NAME="Alpine Linux v3.21"\n')
    w(f"PAQUETS/{P}_paquets.txt", "busybox-1.37.0-r9\ntransmission-cli-4.0.6-r0\n")
    w(f"PAQUETS/{P}_apk_installed.txt", "C:Q1abc\nP:busybox\nV:1.37.0-r9\nA:x86_64\n\nC:Q1def\nP:transmission-cli\nV:4.0.6-r0\nA:x86_64\n\n")
    T(f"PAQUETS/{P}_historique.tar.gz", {"etc/apk/world": "alpine-base\nbusybox\ntransmission-cli\n", "etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.21/main\n"})
    T(f"JOURNAUX/{P}_var_log.tar.gz", {"var/log/messages": "Jan  6 21:00:00 pc05 daemon.info sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/sbin/apk add transmission-cli\nJan  6 21:01:00 pc05 auth.info sshd[12]: Accepted publickey for alice from 10.0.0.7 port 5000 ssh2\n"})
    T(f"RESEAU/{P}_reseau.tar.gz", {"etc/wpa_supplicant/wpa_supplicant.conf": 'network={\n    ssid="ibis-hotel-wifi"\n}\n', "etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n"})
    print("matrice :", sorted(os.listdir(B)))
    return verifier(B)


# Ce que chaque famille DOIT donner. Jusqu'ici ce fichier posait cinq collectes
# et n'en tirait rien : il n'avait aucune assertion, et il passait aussi bien
# sur un extracteur cassé que sur un extracteur juste. Les attentes sont celles
# que les commentaires de chaque bloc annoncent déjà.
ATTENDUS = {
    "PC01_A1_MAT_fedora":   ["rpm", "dnf"],
    "PC02_A1_MAT_debian":   ["dpkg", "apt"],
    "PC03_A1_MAT_opensuse": ["zypp", "rpm"],
    "PC04_A1_MAT_arch":     ["pacman"],
    "PC05_A1_MAT_alpine":   ["apk"],
}


def verifier(base):
    """Sur chacune des cinq : l'extraction tourne, rend des faits, et la
    famille se reconnaît à la source des paquets."""
    import subprocess
    ici = os.path.dirname(os.path.abspath(__file__))
    extraire = os.path.join(ici, "..", "forensic-linux", "scripts", "extraire.py")
    controles = os.path.join(ici, "..", "conformite-linux", "scripts", "controles.py")
    manques = 0
    for prefixe, marqueurs in sorted(ATTENDUS.items()):
        racine = os.path.join(base, prefixe)
        faits = os.path.join(base, prefixe + "-faits.jsonl")
        p = subprocess.run([sys.executable, extraire, racine, "-o", faits],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        constats = os.path.join(base, prefixe + "-constats.jsonl")
        q = subprocess.run([sys.executable, controles, racine, "-o", constats,
                            "--faits", faits],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        lus = []
        if os.path.exists(faits):
            with open(faits, encoding="utf-8") as fh:
                lus = [json.loads(l) for l in fh if l.strip()]
        # Un traceback pendant une PHASE ne fait pas échouer le programme :
        # etape() le rattrape. On regarde donc aussi stderr.
        plante = [l for l in p.stderr.decode("utf-8", "replace").splitlines()
                  if l.startswith("  ! ")]
        utiles = [x for x in lus if x["categorie"] != "limite"]
        sources = " ".join(str(x.get("source", "")) + " " + str(x.get("methode", ""))
                           for x in lus)
        ok = (p.returncode == 0 and q.returncode == 0 and not plante
              and len(utiles) >= 5 and any(m in sources for m in marqueurs))
        manques += not ok
        detail = (f"{len(utiles)} faits hors limite"
                  if ok else
                  f"code {p.returncode}/{q.returncode}, {len(utiles)} faits utiles"
                  + (f", phases en erreur : {plante[0][:60]}" if plante else "")
                  + ("" if any(m in sources for m in marqueurs)
                     else f", aucun marqueur {marqueurs}"))
        print(f"  {'ok ' if ok else 'MANQUE'}  {prefixe:24s} {detail}")
    if manques:
        print(f"{manques} famille(s) mal traitée(s).", file=sys.stderr)
    return 1 if manques else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
