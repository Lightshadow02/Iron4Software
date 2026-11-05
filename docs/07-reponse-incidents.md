# Phase 7 — Réponse aux incidents (ISO 27035)

[← Phase 6](06-risques-conformite.md) · [README](../README.md)

> **Objectif.** Formaliser, à partir de l'incident « Marcus » du 26 août, un plan de réponse conforme aux principes d'ISO/IEC 27035, et préparer la sensibilisation.
>
> Référence : mémoire, Phase 7 (p. 41-44) et Annexe G (p. 59-60).

---

## 7.1 Contexte et nature du plan

Deux niveaux sont distingués :

- **les faits observés** : VM4 compromise sous `IRON4SOFTWARE\test`, processus C2 PID 10852, canal actif, artefacts ransomware, durcissements VM3 / VM4 / VM5 ;
- **les procédures proposées** pour contenir, éradiquer et récupérer lors d'un incident futur.

Ce plan est un **runbook**, pas le journal d'une remédiation : les réinstallations complètes, la rotation globale des comptes, le VPN WireGuard, la restauration Veeam et les campagnes de sensibilisation ne sont pas présentés comme exécutés.

### Faits techniques déclenchant le runbook

| Indicateur | Valeur observée | Conséquence |
|---|---|---|
| Compte compromis | `IRON4SOFTWARE\test` | isoler VM4 et réinitialiser le compte |
| Processus C2 | `powershell.exe` PID 10852 | préserver la mémoire, puis terminer le processus après acquisition |
| Connexion C2 | `10.0.0.3:61000 → 192.168.1.68:4444` ESTABLISHED | bloquer la communication, rechercher l'IOC sur les autres hôtes |
| Artefacts ransomware | `.ironlocked`, `LISEZ_MOI_AVANT.txt`, `ransom_wallpaper.bmp` | contenir, préserver, évaluer la restauration |
| Clé | `syskey.bin` récupérée par la Red Team puis supprimée | ne pas dépendre de la clé de l'attaquant ; restaurer depuis les sauvegardes |

---

## 7.2 Planifier et préparer (pré-incident)

**Équipe de réponse.** Le RSSI (rôle tenu par l'équipe projet) et le PDG (point de contact décisionnaire).

**Inventaire opérationnel** après déconnexion de VM2 : VM3 (DC), VM4 (poste PDG), VM5 (Splunk), VM6 (pfSense). L'externalisation du site vitrine est documentée séparément comme cible.

**Classification des données :**

| Données | Emplacement | Criticité |
|---|---|---|
| Données RH | VM4 | Élevée |
| Données clients et projets | dépôts GitHub privés | **Critique** |
| Journaux de sécurité | VM5 | Moyenne |

**Canaux de signalement à formaliser** : une adresse de sécurité dédiée, un canal téléphonique de secours et une procédure d'escalade **indépendante du SIEM**, pour rester utilisable même si la supervision tombe.

**Prérequis du runbook** (non revendiqués comme déployés) : comptes d'intervention dédiés, secrets stockés hors ligne, outils forensiques vérifiés, supports d'acquisition disponibles avant incident.

---

## 7.3 Détection et signalement

Après durcissement, la capacité de détection a progressé de façon mesurable : la chaîne pfSense → Splunk est opérationnelle, Snort apporte une couche complémentaire, et l'alerting autonome a **détecté automatiquement un balayage de ports** depuis la machine attaquante. La couverture n'est toutefois pas complète.

| Source | Capacité actuelle | État |
|---|---|---|
| pfSense → Splunk | collecte des paquets bloqués, analyse sources / ports | Opérationnel |
| Snort → supervision | détection de signatures et de trafic suspect | Opérationnel |
| Alerting autonome | détection périodique des scans et pics de blocage | Opérationnel |
| Sysmon (VM3, VM4) | télémétrie locale processus / réseau | Déployé |
| VM3 / VM4 → Splunk | centralisation des événements Windows | **À finaliser** |
| WireGuard | contrôle des accès distants | **Cible**, non validée par une preuve |

---

## 7.4 Évaluation et décision — trois niveaux de gravité

| Niveau | Critères | Réponse |
|---|---|---|
| **1 — Incident limité** | un poste, pas de chiffrement | isoler le poste (câble ou GPO d'urgence), analyser avec les outils Sysinternals (Autoruns, TCPView), réintégrer si propre, **escalader au niveau 2** si compromis |
| **2 — Incident majeur** | chiffrement, mouvement latéral suspect, C2 actif | isoler les systèmes concernés, **préserver les preuves**, vérifier la disponibilité des sauvegardes, décider des priorités de continuité selon l'impact réel ; toute bascule vers une infrastructure de secours suppose qu'elle ait été déployée et testée |
| **3 — Incident critique** | compromission AD, exfiltration confirmée, impact métier majeur | envisager l'isolement étendu du LAN, mobiliser les responsables métier et juridiques, **évaluer les obligations de notification**, solliciter une expertise externe si nécessaire |

Au regard de ces critères, l'incident Marcus (chiffrement et C2 actif sur un poste) correspond au **niveau 2**.

---

## 7.5 Réponse — contenir, éradiquer, récupérer

### Contenir

Objectif : empêcher la propagation **tout en préservant les preuves**.

1. **Isoler VM4 par règle réseau, sans l'arrêter** si une acquisition mémoire reste nécessaire : sur pfSense, une règle bloquant la source `10.0.0.3/32` vers toute destination coupe le C2 sans éteindre la machine.
2. **Vérifier le blocage des ports 4444 et 4445/TCP** en sortie WAN depuis VM4.
3. Si VM4 doit être retirée ou reconstruite, appliquer la **procédure AD adaptée** après préservation des preuves : désactivation temporaire de l'objet ordinateur, réinitialisation du canal sécurisé, réintégration contrôlée.
4. **Désactiver ou réinitialiser en priorité `IRON4SOFTWARE\test`**, identité effectivement observée ; dans le scénario visant le PDG, prévoir la rotation de son compte métier s'il a servi à ouvrir l'artefact.
5. **Prévenir tous les employés depuis une adresse non compromise** : débrancher le câble réseau, ne pas ouvrir de pièces jointes, ne pas redémarrer.
6. **Rechercher les IOC sur les autres postes** — échecs d'authentification, PowerShell anormal, connexions C2, créations massives de fichiers, artefacts HTA — et appliquer la même isolation en cas de doute.
7. **Préserver** journaux, dump mémoire et artefacts **avant tout nettoyage**.

### Éradiquer

La preuve établit une compromission sous un compte standard et un C2 persistant, mais **ni un dump des identifiants du domaine ni une élévation SYSTEM**. La réponse doit donc rester **proportionnée** : rotation du compte compromis et des secrets exposés d'abord, élargissement seulement si l'analyse révèle d'autres accès.

- Arrêter le processus malveillant **après acquisition**, supprimer les artefacts, valider l'absence de persistance.

| Composant | Mesure proposée |
|---|---|
| **Active Directory (VM3)** | en cas de risque sur les secrets de domaine : rotation contrôlée, en commençant par le compte compromis et les comptes privilégiés ; éviter une rotation indiscriminée sans procédure de reprise |
| **pfSense (VM6)** | si des secrets d'administration ont pu être exposés : changer les identifiants, révoquer sessions et jetons |
| **Splunk (VM5)** | auditer comptes et jetons, révoquer uniquement ceux potentiellement exposés |
| **Comptes locaux Windows** | renouveler les secrets des machines compromises ou exposées |
| **Clés SSH** | régénérer seulement si leur confidentialité est en doute, documenter la redistribution |

**Reconstruction** — si l'intégrité d'une machine ne peut plus être garantie : reconstruire depuis une source de confiance, restaurer uniquement les données nécessaires, **valider la télémétrie avant remise en production**.

| Machine | Stratégie |
|---|---|
| VM4 | depuis un **template Windows durci** |
| VM3 | **seulement si** l'analyse montre une compromission du domaine |
| VM5 | en **préservant les journaux et la configuration** |
| VM6 | depuis une **configuration de référence** |

La reconstruction complète reste un dernier recours ; aucune réinstallation des quatre machines n'est revendiquée comme réalisée.

### Récupérer

| Priorité | Service | RTO cible | Méthode |
|---|---|---|---|
| 1 | Code source / données métier | 4 h | dépôt distant + sauvegarde indépendante |
| 2 | Active Directory (VM3) | 8 h | restauration / reconstruction selon le niveau de compromission et les sauvegardes validées |
| 3 | SIEM Splunk (VM5) | 12 h | restauration configuration / index, puis validation de l'ingestion |
| 4 | Postes de travail (VM4+) | 24 h | template durci, puis restauration des données vérifiées |
| 5 | Site vitrine (Vercel) | 0 h | non concerné (hors périmètre) |

Les fichiers `.ironlocked` nécessitent la clé correspondante. Dans le laboratoire, une copie conservée par la Red Team permettrait de valider la procédure pédagogique de déchiffrement ; **en situation réelle, le plan de reprise ne doit jamais dépendre d'une clé détenue par l'attaquant**, mais de sauvegardes indépendantes, testées et disponibles hors ligne.

**Critères de sortie de crise** (checklist, pas résultats mesurés) :

- [ ] validation réseau ;
- [ ] contrôle de l'ingestion Splunk ;
- [ ] vérification des comptes et des secrets ;
- [ ] test de restauration ;
- [ ] observation renforcée sur une période définie.

---

## 7.6 Retour d'expérience

1. **Retirer un composant vulnérable peut être plus efficace qu'un durcissement complexe.** La déconnexion de VM2 interrompt le point de pivot ; l'externalisation du site réduirait encore la surface locale, sous réserve d'une analyse de risques fournisseur et d'une validation du déploiement.
2. **Un SIEM n'apporte de valeur que si ses sources sont raccordées et testées.** Le durcissement de VM5 prépare l'index et les services ; les forwarders distants doivent être validés avant de considérer la détection comme complète.
3. **Le facteur humain reste déterminant.** Le dépôt manuel de la charge simule un phishing réussi visant le PDG : c'est un choix de reproductibilité, pas la preuve d'un e-mail réellement reçu.
4. **Les sauvegardes ne valent que si leur restauration est testée.** La politique 3-2-1 est un objectif de résilience ; aucun temps de restauration mesuré n'est revendiqué.
5. **Un plan de réponse écrit après coup n'en est pas vraiment un.** Ce plan a été rédigé après l'attaque : il doit être **révisé chaque année** ou après chaque incident majeur, et **éprouvé par un exercice sur table semestriel**.
6. **La sensibilisation complète le durcissement technique.** Une plateforme de simulation de phishing permettrait de suivre le taux de clic, le taux de téléchargement, le taux de signalement, le délai moyen de signalement et la progression après formation — aucun résultat chiffré n'est revendiqué faute de mesure.

[← Phase 6](06-risques-conformite.md) · [README](../README.md)
