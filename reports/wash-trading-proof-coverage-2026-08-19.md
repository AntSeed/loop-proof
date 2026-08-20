# Wash-Trading Proof Coverage Inventory

Source scan: `90c3bbb3f29831d912ff60dc`

## Summary

- 42 report findings = 18 seller findings + 24 reciprocal-pair findings.
- The predicate supports native funding, direct USDC funding, and authenticated protocol deposits, including seller-funded buyers.
- Multi-funder P1 aggregation is allowed only when every included exact funder funds at least 3 selected buyers.
- 13 of 18 seller findings satisfy 3 buyers, 1,000 USDC, and 50% after funding with one funder.
- 4 fail the single-funder 50% threshold; 1 additional finding passes 50% but remains below 1,000 USDC.
- 39 cases are proof-ready; 0 remain analysis-only for router attribution; 3 fail the predicate.

## Seller Findings

| Priority | Seller | Enforcement status | Support category | Best single-funder result | Multi-funder result | Threshold status |
|---|---|---|---|---|---|---|
| P0 | Flash · `0x0329c5d3920e301740f78d6e17b8d1a11cca9b2c` | proof-ready | closed-cycle the predicate | first_native_funder · 0xd0b238…0b76 · 50 buyers · 42,738.709496 USDC · 95.29% | 50 buyers · 42,748.461892 USDC · 95.31% | passes |
| P0 | CatGPT · `0xb629449e487740c5fb86d7c4ddd51709d692dab4` | proof-ready | protocol-deposit the predicate | primary_usdc_funder · 0xb62944…dab4 · 15 buyers · 21,972.469339 USDC · 92.84% | 15 buyers · 21,972.469339 USDC · 92.84% | passes |
| P1 | StrataCode · `0x6f9b9e63d3f776d359eb2fb0a82d12ee496fbefe` | proof-ready | native exact-funder the predicate | first_native_funder · 0x55d2ee…0e44 · 17 buyers · 10,612.500621 USDC · 73.12% | 24 buyers · 14,507.8487 USDC · 99.96% | passes |
| P1 | GPU-Garden · `0xa06fda7beb9800a442c7f14e27b5b6fb2ab3a89e` | proof-ready | native exact-funder the predicate | first_native_funder · 0x3304e2…566a · 20 buyers · 12,720.017291 USDC · 99.99% | 20 buyers · 12,720.017291 USDC · 99.99% | passes |
| P1 | InferenceLab · `0x74d4ca0dcb2d9140da86dbf7bbe97eef7d4f2f72` | proof-ready | native exact-funder the predicate | first_native_funder · 0x3304e2…566a · 20 buyers · 12,012.48959 USDC · 99.99% | 20 buyers · 12,012.48959 USDC · 99.99% | passes |
| P1 | 0x7adbe9…c915 · `0x7adbe9474e067376da5dea2f757ea3eaa60dc915` | fails-predicate | native exact-funder the predicate | first_native_funder · 0x3304e2…566a · 3 buyers · 5,437.502671 USDC · 46.71% | 14 buyers · 5,437.50488 USDC · 46.71% | fails 50% |
| P1 | TokenShop · `0xbd0cd45b7b486f312460e657701350fab953a3d2` | proof-ready | native exact-funder the predicate | first_native_funder · 0x3304e2…566a · 20 buyers · 11,639.492435 USDC · 99.99% | 20 buyers · 11,639.492435 USDC · 99.99% | passes |
| P1 | Auralis AI \| Legal · `0xca72a6f0a756921a4e303fe88ddbbc193594b659` | proof-ready | native exact-funder the predicate | first_native_funder · 0x18bead…63dd · 6 buyers · 2,678.078089 USDC · 60.18% | 11 buyers · 2,678.09374 USDC · 60.18% | passes |
| P1 | Auralis AI \| Medical · `0xc228219f75ee855e33c874616505406648c78d88` | proof-ready | native exact-funder the predicate | first_native_funder · 0x1b1d21…b53d · 3 buyers · 1,732.594738 USDC · 39.98% | 28 buyers · 3,134.824692 USDC · 72.34% | passes |
| P1 | 0x1734b6…e621 · `0x1734b6f07239fc2c5806b83f054802ca87f8e621` | proof-ready | multi-source exact-funder the predicate | primary_usdc_funder · 0xee7ae8…4055 · 3 buyers · 3,560.557779 USDC · 83.35% | 37 buyers · 3,563.718616 USDC · 83.43% | passes |
| P1 | NoaxAI · `0x94c3f5af394542cfa123f32e17a7a25feeed6758` | proof-ready | multi-source exact-funder the predicate | first_native_funder · 0xdea91d…dcbb · 15 buyers · 3,581.954232 USDC · 99.99% | 15 buyers · 3,581.954232 USDC · 99.99% | passes |
| P1 | surplus-provider · `0xda96465c5ff412bb13a9b919a3247a681f7528f0` | proof-ready | native exact-funder the predicate | first_native_funder · 0x55d2ee…0e44 · 147 buyers · 3,294.462214 USDC · 99.99% | 147 buyers · 3,294.462214 USDC · 99.99% | passes |
| P1 | Prompt-Forge · `0x3a59c0058d6f4d75887aadf6812855a75b9ef1fd` | proof-ready | multi-source exact-funder the predicate | first_native_funder · 0xdea91d…dcbb · 14 buyers · 3,193.660034 USDC · 99.99% | 14 buyers · 3,193.660034 USDC · 99.99% | passes |
| P1 | ClaudeNode · `0x41a609faf354500f5e4af4501b05f045bf0de985` | proof-ready | multi-source exact-funder the predicate | first_native_funder · 0x55d2ee…0e44 · 22 buyers · 2,487.920938 USDC · 99.93% | 22 buyers · 2,487.920938 USDC · 99.93% | passes |
| P1 | 0xddfa54…27fe · `0xddfa54f436de24b909c49763e1604563b96327fe` | proof-ready | native exact-funder the predicate | first_native_funder · 0x3304e2…566a · 3 buyers · 716.95769 USDC · 35.04% | 14 buyers · 1,419.688104 USDC · 69.40% | passes |
| P1 | 0xb269dc…b1a6 · `0xb269dc2c211dfcd926222b4b2b82a731d22fb1a6` | fails-predicate | native exact-funder the predicate | first_native_funder · 0x91604f…c499 · 3 buyers · 739.062551 USDC · 42.25% | 3 buyers · 739.062551 USDC · 42.25% | fails 50% |
| P1 | 0x5cd441…08f1 · `0x5cd4413f15d664afbdab2fc4273c56e215aa08f1` | proof-ready | multi-source exact-funder the predicate | first_native_funder · 0x3304e2…566a · 25 buyers · 1,122.23824 USDC · 95.97% | 25 buyers · 1,122.23824 USDC · 95.97% | passes |
| P1 | 0xc8bd28…f6c9 · `0xc8bd287fd6574519bc937c5c90e7d9687e2df6c9` | fails-predicate | native exact-funder the predicate | first_native_funder · 0x91604f…c499 · 5 buyers · 745.579995 USDC · 73.23% | 10 buyers · 745.848155 USDC · 73.26% | fails 1,000 USDC |

## Reciprocal-Pair Findings

All 24 reciprocal findings require a separate reciprocal-pair predicate; the Flash seller predicate cannot express two-way settlement reciprocity.

| Wallet A | Wallet B | Gross volume | Settlements | Reciprocity | Enforcement status |
|---|---|---:|---:|---:|---|
| `0x1b46b5ed9512dc2ad4c4a3d9ec89aebe4dee3631` | `0xc7e303a65f454c1ac3bd2a88e95e7fa5f6a6946a` | 1,117.40 USDC | 11,105 | 99.50% | proof-ready |
| `0x17cca44fd5c8d5a2e28b9645ec9977d46537c89b` | `0xb88bcda463f6522d5406b935559f09b826cdc17c` | 982.80 USDC | 9,828 | 98.95% | proof-ready |
| `0x1f761c8d047c73e4de85f07f54b5ef4f01d8e3d0` | `0xc9cd64754b9c273522012526da15fee8520a772b` | 862.20 USDC | 8,621 | 98.66% | proof-ready |
| `0x0ecbde32e1dc6c3fb8aada176cea7954316e9696` | `0x1c98fa01dcc641e431346be0767bc7344e889761` | 778.90 USDC | 7,614 | 99.77% | proof-ready |
| `0x3b5f5b27b789dd4848625befca5d85ee49624da9` | `0xddbc2bb655d94251113908701896bbd786af20a2` | 735.7722 USDC | 7,123 | 98.72% | proof-ready |
| `0x40f158cc85f06f272c704822e39943ef1dc168ae` | `0x85f64f9736aeb122e387779a80c5257ad43ba834` | 680.50 USDC | 6,624 | 99.97% | proof-ready |
| `0x97a19f462f880c2cfb768dea465dc1a0eb08ad33` | `0xea8859617ffef68890b92b2df480458cd7a6581c` | 658.30 USDC | 6,362 | 98.40% | proof-ready |
| `0xcccf2236260bfd0d65abc011563b4796b2040366` | `0xd63409b6520b114d4666d8568e925653eae66a30` | 661.10 USDC | 6,333 | 99.97% | proof-ready |
| `0x3639a405bd9a7f943b069e68e70dad28a9583bbc` | `0x8923a4be978521e078e72b92077d59fe2c4deac8` | 560.60 USDC | 5,605 | 98.02% | proof-ready |
| `0x69f915d18ab913f0c86913a94c353b46a5e7baa4` | `0xc92bc8c21a66b5b10fbfdbea8be56b8fee51d0ab` | 489.00 USDC | 4,883 | 99.92% | proof-ready |
| `0x1982cb91d172e4064ea0eb65085234fcd9f2a40f` | `0xb65de8dd31d0967a19c7e9f398fc8a4cc3060abf` | 477.00 USDC | 4,766 | 99.08% | proof-ready |
| `0x05322ba8e1ae2c134d4bf20bbd21b435ae6cd098` | `0x3c5babfb591d405625dffda1635ea4f077d64838` | 451.30 USDC | 4,486 | 99.96% | proof-ready |
| `0x3fdb59a36204f0792d3d051ef4a26b7bc5160ec7` | `0xe93d3458f07a4d3f93f321a234d55cf084a679af` | 450.10 USDC | 4,467 | 99.96% | proof-ready |
| `0x5b281ff194f7fd3f68e9379a7d433c752013024f` | `0x8fb7289428d6b3e3f253294c14d1bfaea7d6c05b` | 448.50 USDC | 4,467 | 99.96% | proof-ready |
| `0x83e57cbffc0d789f57c6ae0b0326385ad715c00f` | `0xc70734320044e6a7934d97b58eaa2df7d102b0f0` | 445.90 USDC | 4,416 | 99.69% | proof-ready |
| `0x6e4dfb6f34ef798b67c6f546b4da15a170e6e8be` | `0x8d9ddb7ae530fde5c6c811cedd893b8028fe41f4` | 437.70 USDC | 4,346 | 99.68% | proof-ready |
| `0x89118d485aab2f427bf4d9a44b09275222b1e4b3` | `0x918e2dbcc1243101d6fa212d0c75b30ec4626bf9` | 423.00 USDC | 4,226 | 100.00% | proof-ready |
| `0x40485259c7dd469f171d0789fb6597c07e32be0e` | `0x4581213a7a271c2424427fe4a991dd5ed7f65492` | 359.10 USDC | 3,591 | 99.94% | proof-ready |
| `0xa76cd6e86dc48e3e7fd24c4807a844b4d6caba27` | `0xe2d4c66359fa70a1fba7985c9ffbdd6c4f9a1848` | 305.70 USDC | 3,048 | 99.67% | proof-ready |
| `0x20e7fb440a5ad18f7b9bae09ae51e806cde38b25` | `0x8c0be23fbf68d6c317addafd59b1dfb42ea6806b` | 254.60 USDC | 2,534 | 100.00% | proof-ready |
| `0x087800d22b7da6dcfef347f1dac6a9e6b7493e9e` | `0x6cedcd162ce26ea07df8562be548fd0597526454` | 203.80 USDC | 2,029 | 100.00% | proof-ready |
| `0x4cf31b431f7559400dcd1269a787dd55d291ca49` | `0x7877aa0c29f7c80a9a46bfd9c05dac8126471ff2` | 81.50 USDC | 766 | 85.23% | proof-ready |
| `0x3ae220b8c315111111249a52296aeb1dd69f972d` | `0x422c3faacdedfd0dea33705ea0000008f9a02e48` | 39.70 USDC | 394 | 93.66% | proof-ready |
| `0x22564606c08e09bef5d8addedefd4c2491a34ee9` | `0x22a856f3aa4080b0eaeebfd7dca97c93b1618e80` | 20.40 USDC | 193 | 100.00% | proof-ready |

## Interpretation

The P1 predicate may aggregate multiple exact-funder cohorts, but each included funder must independently bootstrap at least three selected buyers. This prevents an attacker from combining unrelated one-off buyer funders. Three additional seller findings pass under this hardened multi-funder rule; three still fail the fixed volume or 50% threshold.

This inventory uses archived scan transactions and timestamps only. It generates no zkVM receipt and no production proof. No candidate has settlement volume at the exact same timestamp as its selected funding event, so timestamp ordering creates no boundary ambiguity in this scan.
