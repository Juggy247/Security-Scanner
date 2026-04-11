import argparse
from admin import AdminCLI


def main():
    parser = argparse.ArgumentParser(
        description='Security Scanner Database Administration CLI\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s add-tld tk --risk high --reason "Common phishing TLD"
  %(prog)s list-tlds --json
  %(prog)s add-brand paypal --category financial --priority high
  %(prog)s stats
  %(prog)s import data/threats.json
        """
    )
    
    
    #subparsers = parser.add_subparsers(dest='command', help='Available commands')
    subparsers = parser.add_subparsers(
    dest='command',
    help='Available Commands',
    metavar='Command'
)

    parser_add_tld = subparsers.add_parser('add-tld', help='Add a suspicious TLD')
    parser_add_tld.add_argument('tld', help='TLD to add (without dot)')
    parser_add_tld.add_argument('--risk', default='medium', choices=['low', 'medium', 'high', 'critical'], help='Risk level')
    parser_add_tld.add_argument('--reason', default='', help='Reason for suspicion')
    parser_add_tld.add_argument('--added-by', default='admin', help='Who is adding this')
    
    parser_list_tld = subparsers.add_parser('list-tlds', help='List suspicious TLDs')
    parser_list_tld.add_argument('--include-inactive', action='store_true', help='Include inactive TLDs')
    parser_list_tld.add_argument('--json', action='store_true', help='Output as JSON')
    
    parser_update_tld = subparsers.add_parser('update-tld', help='Update a TLD')
    parser_update_tld.add_argument('tld', help='TLD to update')
    parser_update_tld.add_argument('--risk', choices=['low', 'medium', 'high', 'critical'], help='New risk level')
    parser_update_tld.add_argument('--reason', help='New reason')
    
    parser_remove_tld = subparsers.add_parser('remove-tld', help='Remove a TLD')
    parser_remove_tld.add_argument('tld', help='TLD to remove')
    parser_remove_tld.add_argument('--force', action='store_true', help='Skip confirmation')
    
    
    parser_deactivate_tld = subparsers.add_parser('deactivate-tld', help='Deactivate a TLD')
    parser_deactivate_tld.add_argument('tld', help='TLD to deactivate')
    
    
    
    
    parser_add_brand = subparsers.add_parser('add-brand', help='Add a protected brand')
    parser_add_brand.add_argument('name', help='Brand name')
    parser_add_brand.add_argument('--category', default='general', help='Brand category')
    parser_add_brand.add_argument('--priority', default='medium', choices=['low', 'medium', 'high'], help='Priority level')
    parser_add_brand.add_argument('--added-by', default='admin', help='Who is adding this')
    
    
    parser_list_brand = subparsers.add_parser('list-brands', help='List protected brands')
    parser_list_brand.add_argument('--category', help='Filter by category')
    parser_list_brand.add_argument('--json', action='store_true', help='Output as JSON')
    
    
    parser_remove_brand = subparsers.add_parser('remove-brand', help='Remove a brand')
    parser_remove_brand.add_argument('name', help='Brand name to remove')
    parser_remove_brand.add_argument('--force', action='store_true', help='Skip confirmation')
    
    
   #Blacklist
    parser_add_blacklist = subparsers.add_parser('add-blacklist', help='Add to blacklist')
    parser_add_blacklist.add_argument('domain', help='Domain to blacklist')
    parser_add_blacklist.add_argument('--source', default='manual', help='Source of the blacklist entry')
    parser_add_blacklist.add_argument('--reason', default='', help='Reason for blacklisting')
    parser_add_blacklist.add_argument('--added-by', default='admin', help='Who is adding this')
    
    
    parser_list_blacklist = subparsers.add_parser('list-blacklist', help='List blacklisted')
    parser_list_blacklist.add_argument('--limit', type=int, default=100, help='Maximum number of results')
    parser_list_blacklist.add_argument('--json', action='store_true', help='Output as JSON')
    
    
    parser_search_blacklist = subparsers.add_parser('search-blacklist', help='Search blacklisted')
    parser_search_blacklist.add_argument('query', help='Search query')
    parser_search_blacklist.add_argument('--json', action='store_true', help='Output as JSON')
    
    
    parser_remove_blacklist = subparsers.add_parser('remove-blacklist', help='Remove from blacklist')
    parser_remove_blacklist.add_argument('domain', help='Domain to remove')
    parser_remove_blacklist.add_argument('--force', action='store_true', help='Skip confirmation')
    
    
    #Keyword
    
    parser_add_keyword = subparsers.add_parser('add-keyword', help='Add a suspicious keyword')
    parser_add_keyword.add_argument('keyword', help='Keyword to add')
    parser_add_keyword.add_argument('--category', default='action_words', help='Keyword category')
    parser_add_keyword.add_argument('--risk', default='medium', choices=['low', 'medium', 'high'], help='Risk level')
    
   
    parser_list_keyword = subparsers.add_parser('list-keywords', help='List suspicious keywords')
    parser_list_keyword.add_argument('--category', help='Filter by category')
    parser_list_keyword.add_argument('--json', action='store_true', help='Output as JSON')
    
    
    parser_remove_keyword = subparsers.add_parser('remove-keyword', help='Remove a keyword')
    parser_remove_keyword.add_argument('keyword', help='Keyword to remove')
    parser_remove_keyword.add_argument('--force', action='store_true', help='Skip confirmation')
    
    
    
    
    subparsers.add_parser('stats', help='Show database statistics')
    
    
    parser_import = subparsers.add_parser('import', help='Import data from JSON file')
    parser_import.add_argument('file', help='JSON file to import')
    
    
    parser_export = subparsers.add_parser('export', help='Export data to JSON file')
    parser_export.add_argument('file', help='JSON file to export to')
    
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    
    cli = AdminCLI()
    
    try:
        
        if args.command == 'add-tld':
            cli.add_tld(args.tld, args.risk, args.reason, args.added_by)
        
        elif args.command == 'list-tlds':
            cli.list_tlds(args.include_inactive, args.json)
        
        elif args.command == 'update-tld':
            cli.update_tld(args.tld, args.risk, args.reason)
        
        elif args.command == 'remove-tld':
            cli.remove_tld(args.tld, args.force)
        
        elif args.command == 'deactivate-tld':
            cli.deactivate_tld(args.tld)
        
        elif args.command == 'add-brand':
            cli.add_brand(args.name, args.category, args.priority, args.added_by)
        
        elif args.command == 'list-brands':
            cli.list_brands(args.category, args.json)
        
        elif args.command == 'remove-brand':
            cli.remove_brand(args.name, args.force)
        
        elif args.command == 'add-blacklist':
            cli.add_blacklist(args.domain, args.source, args.reason, args.added_by)
        
        elif args.command == 'list-blacklist':
            cli.list_blacklist(args.limit, args.json)
        
        elif args.command == 'search-blacklist':
            cli.search_blacklist(args.query, args.json)
        
        elif args.command == 'remove-blacklist':
            cli.remove_blacklist(args.domain, args.force)
        
        elif args.command == 'add-keyword':
            cli.add_keyword(args.keyword, args.category, args.risk)
        
        elif args.command == 'list-keywords':
            cli.list_keywords(args.category, args.json)
        
        elif args.command == 'remove-keyword':
            cli.remove_keyword(args.keyword, args.force)
        
        elif args.command == 'stats':
            cli.show_stats()
        
        elif args.command == 'import':
            cli.import_data(args.file)
        
        elif args.command == 'export':
            cli.export_data(args.file)
        
    finally:
        cli.close()


if __name__ == '__main__':
    main()