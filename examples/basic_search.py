"""Search locally and retrieve full evidence."""

from cvecli.services.search import CVESearchService, SearchRequest


def main() -> None:
    reader = CVESearchService()
    page = reader.search(SearchRequest(query="memory corruption", limit=5))
    for record in page["results"]:
        print(record["id"], record["title"], record["cvss"])
    if page["results"]:
        print(reader.get([page["results"][0]["id"]]))


if __name__ == "__main__":
    main()
