# Phase 6 — Gestion des risques et conformité ISO 27001

[← Phase 5](05-re-attaque.md) · [README](../README.md) · [Phase 7 →](07-reponse-incidents.md)

> **Objectif.** Évaluer la maturité sécurité d'Iron4Software, produire une matrice de risques (ISO/IEC 27005) et un plan de mise en conformité (ISO/IEC 27001).
>
> Référence : mémoire, Phase 6 (p. 37-40) et Annexe F (p. 57-58).

---

## 6.1 Matrice de risques (ISO 27005)

La matrice combine des scénarios **observés** dans le laboratoire et des scénarios **plausibles**. Un scénario de risque n'est pas, en soi, la preuve d'une exploitation réussie : la distinction est maintenue pour ne pas transformer une hypothèse de menace en résultat de pentest.

### Échelles

**Vraisemblance (V)** — probabilité qu'un attaquant du profil Marcus (opportuniste, outillage public, motivation financière) réussisse dans l'état initial :

| Niveau | Signification |
|---|---|
| 1–2 | très faible / faible (0-day, ingénierie sociale hautement ciblée) |
| 3 | moyenne (exploit public connu, conditions particulières) |
| 4 | élevée (exploit public, configuration vulnérable exposée, pas de MFA) |
| 5 | très élevée (service exposé sans correctif, mot de passe faible, aucune surveillance) |

**Impact (I)** — conséquence métier pour une TPE de 8 salariés manipulant des données RH sensibles, sans PCA/PRA testé :

| Niveau | Signification |
|---|---|
| 1–2 | mineur / significatif (perturbation ponctuelle, pas de fuite) |
| 3 | important (arrêt partiel, remédiation < 10 k€) |
| 4 | majeur (arrêt complet, perte de données clients, sanction réglementaire probable) |
| 5 | critique (faillite probable, violation RGPD avec notification CNIL, destruction irréversible) |

**Risque = V × I**, avec les seuils :

| Score | Niveau | Traitement attendu |
|---|---|---|
| 1–4 | Faible | surveillance / acceptation possible |
| 5–9 | Modéré | traitement planifié |
| 10–14 | Significatif | mesures correctives nécessaires |
| 15–16 | Élevé | traitement sous 90 jours |
| 17–20 | Critique | traitement immédiat (dès la Phase 4) |
| 21–25 | Très critique | arrêt du service, intervention d'urgence |

### Matrice

| # | Scénario | V | I | Risque | Option de traitement |
|---|---|---|---|---|---|
| R1 | Compromission du service web + pivot vers le LAN | 4 | 5 | **20 — Critique** | **Transfert** (externalisation Vercel) et suppression de VM2 |
| R2 | Phishing du PDG + ransomware | 4 | 5 | **20 — Critique** | **Réduction** (MFA, EDR, sauvegardes) |
| R3 | Compromission de compte (authentification faible) | 3 | 5 | **15 — Élevé** | **Réduction** (MFA, verrouillage, mots de passe robustes, journalisation) |
| R4 | Exposition SMBv1 / risque MS17-010 | 3 | 5 | **15 — Élevé** | **Évitement** (désactivation SMBv1, correctifs, filtrage) |
| R5 | Fuite de données RH | 3 | 5 | **15 — Élevé** | **Réduction** (chiffrement, DLP, ACL) |

### Fiches de risque (Annexe F.1)

**R1 — Compromission du service web et pivot vers le LAN.** L'exploitation de la CVE Apache prévue n'a pas abouti ; l'accès initial est venu d'un webshell volontairement présent. Le risque est donc formulé plus largement comme *la compromission du service web exposé permettant un pivot* — pivot effectivement démontré.
*Traitement :* supprimer VM2, arrêter l'hébergement web local, externaliser le site vitrine, retirer les redirections NAT HTTP/HTTPS. Le chemin de pivot disparaît, mais pas tous les risques liés au site : sécurité des comptes GitHub/Vercel, DNS et chaîne de déploiement restent à la charge de l'entreprise. **Réduction importante + transfert partiel** vers le fournisseur.

**R2 — Phishing du PDG et ransomware.** L'exécution simulée a conduit à un canal de commande, au chiffrement de fichiers (29 annoncés, 30 recensés), à une note de rançon, au changement du fond d'écran et à l'extraction de la clé. C'est l'un des risques les plus importants.
*Réduction :* Defender maintenu, Controlled Folder Access, restriction des macros Office et des fichiers venant d'Internet, blocage HTA, journalisation PowerShell, désactivation de PowerShell v2, Sysmon, MFA sur les comptes sensibles, sensibilisation, sauvegardes 3-2-1.

**R3 — Compromission de comptes.** Mots de passe faibles, pas de MFA, pas de verrouillage, droits trop larges, comptes courants et administratifs confondus.
*Réduction :* MFA pour comptes privilégiés et VPN, longueur et complexité minimales, verrouillage après plusieurs échecs, séparation des comptes, revue régulière des droits, moindre privilège.

**R4 — Exposition SMBv1 / MS17-010.** SMBv1 était prévu comme faiblesse ; il n'était pas exploitable depuis la position de l'attaquant et le contrôle MS17-010 est resté non concluant. Aucune exploitation n'est revendiquée, mais le maintien d'un protocole obsolète reste un risque.
*Traitement :* désactivation de SMBv1, usage de SMBv2/v3, signature SMB, correctifs Windows, filtrage du port 445, segmentation — **évitement** du risque spécifique à SMBv1.

**R5 — Fuite de données RH.** Une compromission d'un poste ou du DC pourrait permettre l'exfiltration de données personnelles. Scénario non exécuté, mais risque métier majeur.
*Réduction :* chiffrement des données sensibles, contrôle strict des droits, moindre privilège, revue des ACL, segmentation, filtrage des flux sortants, journalisation des accès, surveillance des volumes anormaux, éventuelle DLP. **Le risque résiduel reste supérieur aux autres** : une fuite peut encore venir d'un compte légitime compromis ou d'une erreur humaine.

---

## 6.2 Checklist de conformité ISO 27001 (contrôles clés)

| Contrôle (Annexe A) | État avant | État cible | Écart | Statut |
|---|---|---|---|---|
| **A.5.1** Politiques de sécurité de l'information | aucune PSSI, règles techniques isolées sans document central | PSSI rédigée, validée par la direction, communiquée, revue au moins annuellement et après tout incident majeur | Majeur | Partiellement conforme |
| **A.5.15** Contrôle d'accès | pas de MFA, mots de passe faibles, verrouillage insuffisant, compte Invité présent sur VM4, séparation des privilèges insuffisante | MFA comptes privilégiés et VPN, moindre privilège, comptes admin dédiés, politique de mot de passe renforcée, verrouillage, revue trimestrielle | Majeur | Partiellement conforme |
| **A.5.24** Préparation à la gestion des incidents | étapes de réponse pratiquées pendant le scénario, mais aucune procédure organisationnelle avant l'incident | procédure définissant rôles, signalement, escalade, confinement, éradication, conservation des preuves, restauration, communication de crise, retour d'expérience | Modéré | Partiellement conforme |
| **A.8.16** Activités de surveillance | Splunk installé mais sans collecte lors de l'incident | collecte Windows, Sysmon et pfSense centralisée ; détection brute-force, PowerShell suspect, comportements ransomware ; alertes et tableaux de bord | Modéré | En amélioration |

Processus d'incident retenu pour A.5.24 : **Détection → Qualification → Confinement → Éradication → Restauration → Retour d'expérience**.

Le contrôle A.8.15 (Journalisation) est complémentaire ; l'évaluation est limitée aux quatre contrôles demandés par le projet.

---

## 6.3 Politique de sécurité (PSSI) — résumé exécutif

### Périmètre

Infrastructure après durcissement : VM3 (Windows Server / AD), VM4 (poste PDG), VM5 (Splunk), VM6 (pfSense), site vitrine hébergé sur Vercel, comptes utilisateurs et administrateurs, données métier et RH, sauvegardes.

### Gouvernance adaptée à une TPE

| Rôle | Responsabilité |
|---|---|
| **Direction** | valide les politiques et accepte les risques |
| **Administrateur IT interne** | assure l'exploitation |
| **RSSI externe** | intervient environ une journée par semaine |
| **Comité sécurité** (trimestriel) | examine incidents, vulnérabilités, alertes Splunk, correctifs, risques, sauvegardes et actions en cours |

### Exigences clés

1. Tout **accès privilégié** utilise la **MFA** lorsque la technique le permet.
2. Les utilisateurs disposent des **seuls droits nécessaires** (moindre privilège).
3. Les sauvegardes des données critiques suivent la stratégie **3-2-1** et sont **chiffrées** lorsqu'elles contiennent des données sensibles.
4. Une **restauration est testée et documentée au moins une fois par mois**.
5. Toute modification des **règles de pare-feu** est validée par une personne habilitée, documentée et traçable.
6. Les **modifications critiques** du SI font l'objet d'une vérification après mise en œuvre.
7. Les **journaux de sécurité** des systèmes critiques sont centralisés dans Splunk ; les alertes critiques sont analysées dès leur détection.
8. Tout **incident significatif** est signalé au responsable sécurité **sous 24 heures**.
9. Les utilisateurs bénéficient d'une **sensibilisation annuelle** au phishing et aux bonnes pratiques.

---

## 6.4 Plan de sauvegarde 3-2-1

Objectif : limiter les conséquences d'un ransomware ou d'une destruction accidentelle.

- **3 copies** : production, sauvegarde locale, sauvegarde distante ;
- **2 supports différents** : stockage local ou NAS, stockage cloud chiffré ;
- **1 copie hors site**, sur une infrastructure indépendante du système principal — idéalement inaccessible depuis les postes utilisateurs, protégée contre la suppression, chiffrée et vérifiée régulièrement.

| Service | RTO cible |
|---|---|
| Code source et données métier prioritaires | **4 heures** |
| Active Directory | **8 heures** |
| SIEM Splunk | **12 heures** |
| Postes utilisateurs | **24 heures** |

Un test de restauration est réalisé **au minimum une fois par mois**. La mise en œuvre technique est détaillée en [Phase 4](04-durcissement.md#47-sauvegarde-et-continuité--cible-3-2-1).

---

## 6.5 Plan d'actions GRC

| Priorité | Action | Responsable | Échéance |
|---|---|---|---|
| P1 | Formaliser et faire valider la PSSI | RSSI / Direction | < 3 mois |
| P1 | Déployer la MFA sur les comptes privilégiés et le VPN | Administrateur IT | < 3 mois |
| P1 | Mettre en œuvre les sauvegardes 3-2-1 | Administrateur IT | < 3 mois |
| P1 | Formaliser la procédure de réponse aux incidents | RSSI | < 3 mois |
| P2 | Finaliser la collecte des journaux Splunk | Administrateur IT | < 3 mois |
| P2 | Déployer et tester les règles d'alerte Splunk | Administrateur IT / RSSI | < 3 mois |
| P2 | Réaliser une revue des comptes et privilèges | Administrateur IT | trimestriel |
| P2 | Tester la restauration des sauvegardes | Administrateur IT | mensuel |
| P2 | Sensibiliser les utilisateurs au phishing | RSSI | annuel |
| P3 | Réaliser un nouvel audit / pentest | RSSI / Prestataire | annuel |

## Ce que la phase a appris

- **Ne pas confondre scénario de risque et résultat de test** : R4 et R5 sont évalués comme risques sans être présentés comme exploités.
- **Trois options de traitement ISO 27005** (transfert, réduction, évitement) trouvent une application concrète, même à l'échelle d'une TPE ; aucun des cinq risques n'est jugé acceptable en l'état.
- **Une gouvernance légère mais réelle** (RSSI externe à temps partiel, comité trimestriel) est plus crédible pour huit salariés qu'une organisation calquée sur un grand groupe.

[← Phase 5](05-re-attaque.md) · [README](../README.md) · [Phase 7 →](07-reponse-incidents.md)
