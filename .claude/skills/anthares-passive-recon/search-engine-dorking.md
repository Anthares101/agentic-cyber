# Search Engine Dorking & Archived Content

Dorks let you turn a general-purpose search engine into a targeted recon tool: find exposed configs, login portals, leaked credentials, indexed S3 buckets, file dumps, and more.

## Google Hacking

Google dorking - also known as **Google hacking** - returns information that is difficult to locate through simple search queries. Using this technique, information not intended for public access can be discovered.

The **Google Hacking Database (GHDB)** is the authoritative source for ready-made dorks:

- **GHDB:** https://www.exploit-db.com/google-hacking-database/

Other curated dork collections:

| Source | URL |
|---|---|
| Google Hacking - Pentest Tools | https://pentest-tools.com/information-gathering/google-hacking |
| Offensive Security Cheatsheet (HAAX) | https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/ |

> **Tip:** Sometimes other search engines like **Brave** have information Google does not. Always try at least one alternative engine for the same dork.

## Google and Bing search operators

| Operator | Description |
|---|---|
| `"Search Term"` | Exact phrase within quotes |
| `-` | Remove pages that mention a given term |
| `+` | Force Google to return common words that might otherwise be discarded |
| `OR` | Either term |
| `site:` | Within a given domain |
| `filetype:` | A certain file type |
| `intitle:` | Word(s) in the page title |
| `inurl:` | Word(s) in the URL |
| `intext:` | Word(s) in the page body |
| `inanchor:` | Word(s) in links pointing to the page |
| `cache:` | Most recent cache of a webpage |
| `IP:` | **Bing only:** results based on a given IP |
| `linkfromdomain:` | **Bing only:** links on the given domain |

### Additional Google features

- **Search Tools → Custom Range:** narrows results to a specific time window. Useful for finding leaks that appeared after a known incident.
- **Google Images** (https://images.google.com/): reverse image search - the most powerful for finding where a photo, badge, or screenshot has appeared.

### Useful starter dorks

```
site:target.com filetype:pdf confidential
site:target.com inurl:admin
site:target.com intitle:"index of"
site:pastebin.com "target.com"
site:github.com "target.com" password
"@target.com" -site:target.com filetype:xls
site:s3.amazonaws.com "target"
```

## Yandex search operators

Yandex operates the largest search engine in Russia (~65% market share) and indexes content Google does not, particularly Russian-language, post-Soviet, and previously-removed content.

| Example | Description |
|---|---|
| `"I * music"` | Asterisk (`*`) wildcard for any word |
| `Cheshire cat \| hatter \| Alice` | Search for any word in query (works on Google too) |
| `croquet +flamingo` | Mandate page contains "flamingo" but not "croquet" |
| `rhost:org.wikipedia.*` | Reverse host search |
| `mime:pdf` | Specific file type |
| `!Curiouser !and !curiouser` | Multiple identical-word matches |
| `Twinkle twinkle little -star` | Exclude term |
| `lang:en` | Narrow by language |
| `date:200712*`, `date:20071215..20080101`, `date:>20091231` | Narrow by date or date range |

## Other alternative search engines

| Engine | URL | What it's good for |
|---|---|---|
| **Carrot2** | https://carrot2.org | Clustering search engine - groups results into topics |
| **Exalead** | https://www.exalead.com/search | Finds documents containing the search term |
| **Million Short** | https://millionshort.com | Removes the top-1M most popular sites - surfaces obscure pages |
| **Global File Search** | https://globalfilesearch.com | Indexes 243 TB of files on public FTP servers |

## Searching for archived information

Old content is often gold - removed admin panels, leaked docs, deindexed errors. Search engines themselves keep caches:

- **Google and Bing:** both offer a cached view of results.
- **Wayback Machine:** http://archive.org/web/
- **Archive Today:** http://archive.is/

Wayback supports `https://web.archive.org/web/*/target.com/*` to enumerate every archived URL on the domain - excellent for finding endpoints that are still live but no longer linked.
