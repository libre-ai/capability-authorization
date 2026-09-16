<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Written for the retained Libre AI portfolio on 2026-09-14; earlier source documents and revisions retain their original licensing. -->

# Libre AI Capability Authorization

## Usage visé

Donner aux permissions Biscuit explicites et délimitées utilisées par les services un foyer technique distinct. Une décision d’autorisation indique si une action précise est permise selon les faits et la politique applicables ; elle ne constitue pas à elle seule une connexion utilisateur ou une approbation métier.

## Candidats existants et limites

Les anciennes sources contiennent des composants d’émission, d’atténuation, de vérification, de révocation et de rotation de clés. Leur qualification historique n’admet pas un nouveau paquet ou émetteur opérationnel dans cette destination. Ce candidat documentaire ne fournit aucun jeton utilisable, clé de service ou service de permissions déployé.

## Frontières d’autorité et contrats proposés

L’authentification reste dans la responsabilité Auth associée à Missions. La session et l’appartenance à une organisation sont des faits distincts dont l’autorité réelle doit être qualifiée. Une demande de permission identifie sa ressource, son action et son contexte d’autorité ; le refus reste explicite lorsque des faits ou habilitations requis manquent. L’atténuation peut restreindre un mandat existant, pas l’élargir. Les formats et politiques canoniques conservent leurs autorités désignées.

## Critères d’activation

Qualifier l’émetteur, le vérificateur et un consommateur réel avec une évaluation bornée des politiques. Tester les jetons altérés, clés non prises en charge, expirations, révocations, atténuations et refus entre organisations, d’abord avec des identifiants synthétiques. Vérifier que les faits de requête faisant autorité ne peuvent pas être fournis par un détenteur de jeton non fiable. Distinguer les éléments d’authentification navigateur, les clés de permission des services et les clés de signature Git finale.

La qualification suit le périmètre réellement retenu. Un module candidat peut être admis séparément avec son consommateur et ses preuves ; les critères de parcours complet s’appliquent au produit ou à l’intégration correspondante. Un noyau pur ne nécessite pas une intégration de worker, de base de données ou de relais hors de son périmètre. Ni l’admission d’un module ni l’existence documentaire de ce dépôt ne nécessitent un parcours Missions complet.

[English](README.md)

## Navigation du portefeuille

Ces liens décrivent le portefeuille retenu visé. La disponibilité publique et l’accessibilité ne sont pas vérifiées pour ce candidat privé.

### Produits

- [Libre AI Work Supervision](https://github.com/libre-ai/ai-work-supervision)
- [Libre AI Model Policy](https://github.com/libre-ai/ai-model-policy)
- [Libre AI Practice Workbench](https://github.com/libre-ai/ai-practice-workbench)
- [Libre AI Learning Session Facilitation](https://github.com/libre-ai/learning-session-facilitation)
- [Libre AI Personal Knowledge Notebook](https://github.com/libre-ai/personal-knowledge-notebook)
- [Libre AI Information Feed Filter](https://github.com/libre-ai/information-feed-filter)
- [Libre AI Travel Itinerary Planner](https://github.com/libre-ai/travel-itinerary-planner)
- [Libre AI Public Vote Comparison](https://github.com/libre-ai/public-vote-comparison)

### Composants et outils

- [Libre AI Application Development Toolkit](https://github.com/libre-ai/application-development-toolkit)
- [Libre AI Schemas And Contracts](https://github.com/libre-ai/schemas-and-contracts)
- [Libre AI Collaborative Data Sync](https://github.com/libre-ai/collaborative-data-sync)
- [Libre AI Execution Continuity Evaluator](https://github.com/libre-ai/execution-continuity-evaluator)
- [Libre AI Execution Sandbox](https://github.com/libre-ai/execution-sandbox)
- [Libre AI Capability Authorization](https://github.com/libre-ai/capability-authorization)
- [Libre AI Organization Data Lifecycle](https://github.com/libre-ai/organization-data-lifecycle)
- [Libre AI Database Policy Inspector](https://github.com/libre-ai/database-policy-inspector)
- [Libre AI Artifact Verification](https://github.com/libre-ai/artifact-verification)

### Projet

- [Libre AI](https://github.com/libre-ai/.github)
- [Libre AI Project Website](https://github.com/libre-ai/project-website)
- [Libre AI Project Governance](https://github.com/libre-ai/project-governance)



---

## Source éditoriale revue

[Matière revue](https://github.com/libre-ai/capability-authorization/blob/5280ec02af3e0f5e66795e9db8afe974ef78a316/docs/portfolio-material.json)

SHA-256: `174f9b0da939b680c004cabfee5d12eaf277ff23b5d3817d8bc724ed0ceea945`
