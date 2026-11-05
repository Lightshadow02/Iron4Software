# Phase 5 — Ré-attaque après durcissement

[← Phase 4](04-durcissement.md) · [README](../README.md) · [Phase 6 →](06-risques-conformite.md)

> **Objectif.** Rejouer les vecteurs de la Phase 2 pour vérifier que le durcissement les a neutralisés, et comparer avant / après.
>
> Référence : mémoire, Phase 5 (p. 35-36) et Annexe E (p. 56-57). Cette page présente uniquement les résultats.

---

## Méthodologie

La ré-évaluation porte **uniquement sur les vecteurs démontrés en Phase 2** : exposition web et pivot, exécution de la charge sur VM4, exposition SMBv1. Aucun résultat de devinage de mot de passe n'est intégré, faute de preuve correspondante.

## Résultats par vecteur

### 1. Pivot via le serveur web (VM2 → LAN)

- **Avant** : le serveur web compromis servait de tête de pont vers tout le LAN.
- **Après** : VM2 est déconnectée ; le point de pivot n'est plus disponible dans les mêmes conditions.
- L'externalisation du site vitrine reste une architecture cible, non un résultat de cette ré-évaluation.

### 2. Phishing scénarisé / fichier HTA (VM4)

- **Avant** : la charge déposée sur VM4 s'exécutait et ouvrait une session sous `IRON4SOFTWARE\test`.
- **Après** : une nouvelle tentative de récupération du même fichier est **détectée et mise en quarantaine par Windows Defender** (détection initiale le 29/08/2026 à 19:14:22, `ActionSuccess: True`). Le fichier de téléchargement partiel du navigateur est également intercepté à 19:13:37.
- **`DidThreatExecute: False`** : la menace n'a pas été exécutée. La protection des téléchargements est active.
- `mshta.exe` reste présent, mais le vecteur d'entrée est neutralisé, et **Controlled Folder Access** empêcherait en outre le chiffrement des répertoires protégés.

### 3. SMBv1 / MS17-010 (VM3)

- **Avant** : SMBv1 activé, mais le contrôle MS17-010 n'avait confirmé aucune vulnérabilité exploitable.
- **Après** : désactivation de SMBv1 demandée et signature SMB renforcée ; `RestartNeeded: True`. Le risque est traité par suppression du protocole, **sous réserve de finalisation après redémarrage** et de validation post-boot.

## Synthèse comparative

| Vecteur | Phase 2 (avant) | Phase 5 (après) | Évaluation |
|---|---|---|---|
| Pivot via VM2 | Succès | VM2 déconnectée ; pivot indisponible | **Chaîne interrompue** dans le laboratoire |
| Phishing scénarisé / HTA | Exécution démontrée (charge déposée) | Détection Defender, quarantaine, non exécutée | **Bloqué** |
| SMBv1 / MS17-010 | SMBv1 activé ; test non concluant | Désactivation demandée ; redémarrage requis | **Risque fortement réduit**, validation post-redémarrage requise |

## Ce que la phase a appris

- Plusieurs **conditions nécessaires** à la chaîne initiale ont été supprimées ou renforcées : plus de pivot, poste protégé, protocole obsolète en cours de retrait.
- La ré-attaque **n'est pas résumée par un pourcentage** : pas de « 100 % → 0 % » artificiel, pas de test de mot de passe ni d'EternalBlue revendiqué. Chaque résultat reste limité à ce qui a été rejoué ou vérifié.
- Le retrait d'un composant (VM2) neutralise toute une classe de risques pour un effort modeste — argument repris dans la [matrice de risques](06-risques-conformite.md).

[← Phase 4](04-durcissement.md) · [README](../README.md) · [Phase 6 →](06-risques-conformite.md)
