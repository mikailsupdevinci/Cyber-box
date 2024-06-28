```markdown
# Cyber-Box

## Introduction

Cyber-Box est une toolbox de cybersécurité automatisée développée pour faciliter et accélérer la réalisation de tests d'intrusion. Elle intègre diverses fonctionnalités pour découvrir les services, détecter les vulnérabilités, analyser les mots de passe, tester l'authentification, exploiter les vulnérabilités et effectuer des analyses post-exploitation.

## Fonctionnalités

1. **Découverte de services**
2. **Détection des systèmes d'exploitation**
3. **Analyse des vulnérabilités spécifiques**
4. **Analyse des en-têtes HTTP**
5. **Scan Web avec Nikto**
6. **Scan réseau avec OpenVAS**
7. **Bruteforce SSH**
8. **Analyse des mots de passe**
9. **Test d'authentification**
10. **Exploitation des vulnérabilités**
11. **Analyse post-exploitation**
12. **Génération de rapports**

## Installation

### Prérequis

- Python 3.11
- pip

### Cloner le dépôt

```bash
git clone https://github.com/votreutilisateur/Cyber-Box.git
cd Cyber-Box
```

### Installer les dépendances

```bash
pip install -r requirements.txt
```

## Utilisation

### Lancement de la toolbox

```bash
python3 main.py
```

### Fonctionnalités disponibles

1. **Découverte de services**

   ```bash
   Enter your choice: 1
   ```

   Cette option permet de découvrir les services disponibles sur un réseau spécifié.

2. **Détection des systèmes d'exploitation**

   ```bash
   Enter your choice: 2
   ```

   Cette option permet de détecter les systèmes d'exploitation des hôtes présents sur le réseau.

3. **Scan des vulnérabilités spécifiques**

   ```bash
   Enter your choice: 4
   ```

   Cette option permet de scanner des vulnérabilités spécifiques sur un réseau ou une IP donnée.

4. **Analyse des en-têtes HTTP**

   ```bash
   Enter your choice: 6
   ```

   Cette option permet d'analyser les en-têtes HTTP pour détecter des vulnérabilités potentielles.

5. **Scan Web avec Nikto**

   ```bash
   Enter your choice: 7
   ```

   Cette option permet de lancer un scan web sur une URL spécifique en utilisant Nikto.

6. **Scan réseau avec OpenVAS**

   ```bash
   Enter your choice: 8
   ```

   Cette option permet de lancer un scan réseau complet en utilisant OpenVAS.

7. **Run All Scans**

   ```bash
   Enter your choice: 9
   ```

   Cette option permet de lancer toutes les analyses de manière séquentielle sur un réseau ou une IP donnée.

## Configuration

### OpenVAS

Pour utiliser les fonctionnalités d'OpenVAS, vous devez configurer votre scanner OpenVAS avec les informations correctes (nom d'hôte, port, nom d'utilisateur, mot de passe) dans le script `openvas_scanner.py`.

### Bruteforce SSH

Pour utiliser la fonctionnalité de bruteforce SSH, vous devez fournir un fichier de mots de passe et de noms d'utilisateur.

```python
python3 ssh_bruteforce.py --target TARGET_IP --user-list users.txt --pass-list passwords.txt
```

## Structure du projet

- `main.py`: Fichier principal pour exécuter la toolbox.
- `toolbox/`: Contient tous les modules et scripts de la toolbox.
  - `discovery.py`: Scripts pour la découverte de services et la détection des systèmes d'exploitation.
  - `vulnerability_detection.py`: Scripts pour l'analyse des vulnérabilités spécifiques.
  - `openvas_scanner.py`: Scripts pour l'intégration d'OpenVAS.
  - `ssh_bruteforce.py`: Scripts pour le bruteforce SSH.
  - `reporting.py`: Scripts pour la génération de rapports.
- `requirements.txt`: Fichier listant toutes les dépendances nécessaires.

## Notes

- **Usage personnel**: Cette toolbox est dédiée à un usage personnel. Toute utilisation à mauvais escient pourrait avoir des répercussions légales.

## Auteurs

- Mikail ALBAYRAK

## Licence

Ce projet est sous licence MIT.
