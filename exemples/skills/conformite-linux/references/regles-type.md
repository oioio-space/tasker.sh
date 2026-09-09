# Règles que l'on rencontre, et le contrôle qui y répond

**Ce n'est pas la charte de votre entreprise.** C'est le répertoire des règles
qu'une charte informatique contient le plus souvent, avec le contrôle que cette
collecte permet. Deux usages :

- **comparer** : retrouver, dans la charte fournie, la règle qui correspond à
  un constat — sans jamais la remplacer par celle d'ici ;
- **repérer les trous** : une règle absente de la charte alors qu'un constat la
  réclamerait est une information pour qui écrira la prochaine version.

Chaque ligne : la règle telle qu'on la rencontre, le constat qui la vérifie, et
ce que le contrôle **ne prouve pas**.

---

## Comptes et identification

| règle courante | constat | ce que ça ne prouve pas |
|---|---|---|
| « chaque agent dispose d'un compte nominatif » | plusieurs comptes partagent le même dossier | qui s'en est servi — un dossier partagé rend justement l'attribution impossible |
| « nul ne se sert du compte d'un autre » | thème `partage` : fichiers d'un autre propriétaire dans le dossier personnel ; `su` ou `sudo -u` vers un compte local ; une clé SSH acceptée par deux comptes ; deux origines pour le même compte à quelques minutes | **qui tenait le clavier**. Un fichier de B chez A dit que B a écrit là — par sa session ou par sudo. Deux origines peuvent être une personne et deux machines. Chaque trace se cite avec sa limite |
| « les comptes à privilèges sont déclarés et nominatifs » | compte disposant des droits de root (uid 0) | que le compte soit illégitime : il peut être déclaré |
| « les comptes inutilisés sont désactivés » | *pas de contrôle direct* — croiser les comptes de `passwd` avec les sessions de `faits.jsonl` | — |

## Mots de passe et authentification

| règle courante | constat | ce que ça ne prouve pas |
|---|---|---|
| « tout compte est protégé par un mot de passe » | compte sans mot de passe | — c'est direct |
| « les mots de passe sont renouvelés périodiquement » | mot de passe sans expiration ; `PASS_MAX_DAYS` très long | que le mot de passe soit ancien : seule la politique est lue, pas la date du dernier changement |
| « les mots de passe respectent une robustesse minimale » | hachage MD5 (`$1$`) | la robustesse du mot de passe lui-même : le hachage est irréversible, on ne juge que l'algorithme |
| « l'élévation de privilèges est tracée et authentifiée » | `sudo NOPASSWD` | qui l'a posé — souvent le service informatique |
| « l'accès distant se fait par clé, non par mot de passe » | `PasswordAuthentication yes` | qu'il ait servi ainsi : croiser avec les `Accepted password` du journal |
| « la connexion directe au compte root est interdite » | `PermitRootLogin yes` | qu'elle ait eu lieu : croiser avec le journal |

## Secrets

| règle courante | constat | ce que ça ne prouve pas |
|---|---|---|
| « les clés privées sont protégées par une phrase de passe » | clé privée SSH sans phrase de passe | que la clé ait été volée |
| « aucun identifiant n'est enregistré en clair » | `.netrc`, `.git-credentials`, fichier d'identifiants | que l'identifiant soit encore valide |
| « les secrets ne sont pas saisis en argument de commande » | mot de passe ou jeton dans l'historique | **la date** : un historique n'est pas daté par défaut |
| « les mots de passe ne sont pas enregistrés dans le navigateur » | site avec un mot de passe enregistré, dans `faits.jsonl` (« mot de passe enregistré dans le navigateur ») | l'identifiant ni le secret : seul le **site** est lu. Un site professionnel enregistré peut être toléré, la charte le dit |

## Durcissement du poste

| règle courante | constat | ce que ça ne prouve pas |
|---|---|---|
| « les protections du système sont maintenues actives » | SELinux en `permissive` ou `disabled` | qui l'a désactivé, ni quand |
| « un pare-feu est actif » | `ufw` désactivé ; aucune configuration de pare-feu | l'état réel au moment des faits : on lit une configuration, pas un état. **Une absence de configuration n'est pas une absence de pare-feu** |
| « les disques des postes nomades sont chiffrés » | volume chiffré déclaré (`crypttab`), dans `faits.jsonl` | que les données sensibles y étaient |

## Usages

| règle courante | constat | ce que ça ne prouve pas |
|---|---|---|
| « les supports amovibles sont chiffrés et déclarés » | support amovible monté, avec son **numéro de série** dans `faits.jsonl` | **ce qui y a été copié** — la clé n'est pas dans la collecte. Croiser la timeline et `recently-used.xbel` pour montrer une lecture ou une écriture |
| « les données de l'entreprise ne sortent pas par des services personnels » | service de stockage personnel en ligne présent dans un profil | **que des fichiers y soient partis**. Une visite n'est pas un transfert : ne franchissez pas ce pas sans un fait qui le montre |
| « la messagerie professionnelle est seule utilisée pour le travail » | service de messagerie personnelle présent dans un profil | l'usage qui en a été fait |
| « les outils d'IA générative sont interdits / encadrés » | service d'IA générative présent dans un profil | ce qui y a été saisi — aucune trace n'en subsiste côté poste |
| « l'installation de logiciels est réservée au service informatique » | programme installable dans un dossier personnel ; paquet posé puis retiré (`faits.jsonl`) | qu'il ait été exécuté |
| « aucun outil d'accès distant n'est installé » | service d'accès distant grand public dans un profil | son installation : une visite au site n'est pas une installation |

## Règles qu'une collecte ne peut pas vérifier

À citer dans « Règles non vérifiables », avec ce qu'il faudrait pour les
vérifier :

| règle | pourquoi | ce qu'il faudrait |
|---|---|---|
| « l'agent verrouille sa session en s'absentant » | aucune trace de verrouillage dans la collecte | les journaux de session graphique, non collectés |
| « les données sont sauvegardées sur les serveurs » | on ne voit pas ce qui est ailleurs | l'inventaire des serveurs |
| « l'agent signale tout incident » | rien sur le poste ne le montre | les tickets du service |
| « les mots de passe ne sont pas partagés » | invérifiable par nature | — |
| « le poste n'est pas prêté » | un compte a agi ; qui tenait le clavier reste inconnu | contrôle d'accès physique |
| « la confidentialité est respectée » (formulation générale) | trop large pour un contrôle | à découper en règles concrètes dans la prochaine charte |

---

## Deux avertissements pour la rédaction

**Une visite n'est pas un transfert.** Le constat le plus fréquent — un service
de stockage personnel dans l'historique — établit qu'un site a été consulté. Il
n'établit pas qu'un fichier est parti. Le pas se franchit seulement avec un
fait : un fichier apparu dans `~/Téléchargements`, une écriture dans la
timeline au moment de la visite, une entrée dans la table `downloads`. Sans
cela, écrivez la visite, et écrivez que le transfert n'est pas établi.

**Une configuration n'est pas un état.** `ufw` désactivé dans un fichier dit ce
que le fichier dit. La machine était peut-être protégée autrement, ou ce
réglage date d'après les faits examinés. Le dire coûte une phrase et évite un
rapport faux.
