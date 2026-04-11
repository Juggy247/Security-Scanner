from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from scanner.config import MongoDbConfig
import json
from datetime import datetime

# Create Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

db = MongoDbConfig()


#dashboard part
@admin_bp.route('/')
@admin_bp.route('/dashboard')
def dashboard():
    try:
        stats = {
            'tlds': db.suspicious_tlds.count_documents({'is_active': True}),
            'brands': db.brands.count_documents({'is_active': True}),
            'blacklist': db.blacklisted_domains.count_documents({'is_active': True}),
            'keywords': db.suspicious_keywords.count_documents({'is_active': True}),
        }
        
        tld_risks = {}
        for risk in ['low', 'medium', 'high', 'critical']:
            tld_risks[risk] = db.suspicious_tlds.count_documents({
                'is_active': True, 
                'risk_level': risk
            })
        
        keyword_risks = {}
        for risk in ['low', 'medium', 'high']:
            keyword_risks[risk] = db.suspicious_keywords.count_documents({
                'is_active': True,
                'risk_level': risk
            })
        

        recent_tlds = list(db.suspicious_tlds.find({'is_active': True})
                          .sort('added_date', -1).limit(5))
        recent_brands = list(db.brands.find({'is_active': True})
                            .sort('added_date', -1).limit(5))
        
        return render_template('admin/dashboard.html',
                             stats=stats,
                             tld_risks=tld_risks,
                             keyword_risks=keyword_risks,
                             recent_tlds=recent_tlds,
                             recent_brands=recent_brands)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return render_template('admin/dashboard.html', stats={}, error=str(e))


#tld part
@admin_bp.route('/tlds')
def tlds_list():
    
    include_inactive = request.args.get('inactive', 'false') == 'true'
    query = {} if include_inactive else {'is_active': True}
    
    tlds = list(db.suspicious_tlds.find(query).sort('tld', 1))
    
    return render_template('admin/tlds_list.html', 
                         tlds=tlds, 
                         include_inactive=include_inactive)


@admin_bp.route('/tlds/add', methods=['GET', 'POST'])
def tlds_add():
   
    if request.method == 'POST':
        tld = request.form.get('tld', '').strip().lower().replace('.', '')
        risk_level = request.form.get('risk_level', 'medium')
        reason = request.form.get('reason', '').strip()
        added_by = request.form.get('added_by', 'admin').strip()
        
        if not tld:
            flash('TLD is required', 'error')
            return redirect(url_for('admin.tlds_add'))
        
        success = db.add_suspicious_tld(tld, risk_level, reason, added_by)
        
        if success:
            flash(f'Successfully added TLD: .{tld}', 'success')
            return redirect(url_for('admin.tlds_list'))
        else:
            flash(f'TLD .{tld} already exists', 'error')
    
    return render_template('admin/tlds_form.html', action='Add', tld=None)


@admin_bp.route('/tlds/edit/<tld>', methods=['GET', 'POST'])
def tlds_edit(tld):
    
    if request.method == 'POST':
        updates = {}
        
        if request.form.get('risk_level'):
            updates['risk_level'] = request.form.get('risk_level')
        if request.form.get('reason'):
            updates['reason'] = request.form.get('reason')
        
        if updates:
            success = db.update_tld(tld, **updates)
            if success:
                flash(f'Successfully updated TLD: .{tld}', 'success')
                return redirect(url_for('admin.tlds_list'))
            else:
                flash(f'Failed to update TLD: .{tld}', 'error')
    
    # Get current TLD data
    tld_data = db.get_tld_details(tld)
    
    return render_template('admin/tlds_form.html', 
                         action='Edit', 
                         tld=tld_data)


@admin_bp.route('/tlds/delete/<tld>', methods=['POST'])
def tlds_delete(tld):

    success = db.delete_tld(tld)
    
    if success:
        flash(f'Successfully deleted TLD: .{tld}', 'success')
    else:
        flash(f'Failed to delete TLD: .{tld}', 'error')
    
    return redirect(url_for('admin.tlds_list'))


@admin_bp.route('/tlds/deactivate/<tld>', methods=['POST'])
def tlds_deactivate(tld):
    
    success = db.deactivate_tld(tld)
    
    if success:
        flash(f'Successfully deactivated TLD: .{tld}', 'success')
    else:
        flash(f'Failed to deactivate TLD: .{tld}', 'error')
    
    return redirect(url_for('admin.tlds_list'))

#brand part

@admin_bp.route('/brands')
def brands_list():
    
    category = request.args.get('category')
    
    query = {'is_active': True}
    if category:
        query['category'] = category
    
    brands = list(db.brands.find(query).sort('brand_name', 1))
    categories = db.get_brand_categories()
    
    return render_template('admin/brands_list.html', 
                         brands=brands, 
                         categories=categories,
                         selected_category=category)


@admin_bp.route('/brands/add', methods=['GET', 'POST'])
def brands_add():
    
    if request.method == 'POST':
        brand_name = request.form.get('brand_name', '').strip().lower()
        category = request.form.get('category', 'general').strip()
        added_by = request.form.get('added_by', 'admin').strip()
        
        if not brand_name:
            flash('Brand name is required', 'error')
            return redirect(url_for('admin.brands_add'))
        
        success = db.add_brand(brand_name, category, added_by=added_by)
        
        if success:
            flash(f'Successfully added brand: {brand_name}', 'success')
            return redirect(url_for('admin.brands_list'))
        else:
            flash(f'Brand {brand_name} already exists', 'error')
    
    categories = db.get_brand_categories()
    return render_template('admin/brands_form.html', 
                         action='Add', 
                         brand=None,
                         categories=categories)


@admin_bp.route('/brands/delete/<brand_name>', methods=['POST'])
def brands_delete(brand_name):
    
    success = db.delete_brand(brand_name)
    
    if success:
        flash(f'Successfully deleted brand: {brand_name}', 'success')
    else:
        flash(f'Failed to delete brand: {brand_name}', 'error')
    
    return redirect(url_for('admin.brands_list'))


#blacklist part

@admin_bp.route('/blacklist')
def blacklist_list():
    
    page = int(request.args.get('page', 1))
    per_page = 50
    search_query = request.args.get('search', '').strip()
    
    query = {'is_active': True}
    
    if search_query:
        query['domain'] = {'$regex': search_query, '$options': 'i'}
    
    
    total = db.blacklisted_domains.count_documents(query)
    
    domains = list(db.blacklisted_domains.find(query)
                  .sort('added_date', -1)
                  .skip((page - 1) * per_page)
                  .limit(per_page))
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('admin/blacklist_list.html',
                         domains=domains,
                         page=page,
                         total_pages=total_pages,
                         search_query=search_query,
                         total=total)


@admin_bp.route('/blacklist/add', methods=['GET', 'POST'])
def blacklist_add():
    
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        source = request.form.get('source', 'manual').strip()
        reason = request.form.get('reason', '').strip()
        added_by = request.form.get('added_by', 'admin').strip()
        
        if not domain:
            flash('Domain is required', 'error')
            return redirect(url_for('admin.blacklist_add'))
        
        success = db.add_blacklisted_domain(domain, source, reason, added_by)
        
        if success:
            flash(f'Successfully blacklisted: {domain}', 'success')
            return redirect(url_for('admin.blacklist_list'))
        else:
            flash(f'Domain {domain} is already blacklisted', 'error')
    
    return render_template('admin/blacklist_form.html', action='Add')


@admin_bp.route('/blacklist/delete/<domain>', methods=['POST'])
def blacklist_delete(domain):
    
    success = db.delete_blacklisted_domain(domain)
    
    if success:
        flash(f'Successfully removed from blacklist: {domain}', 'success')
    else:
        flash(f'Failed to remove domain: {domain}', 'error')
    
    return redirect(url_for('admin.blacklist_list'))

#keyword part

@admin_bp.route('/keywords')
def keywords_list():
    
    category = request.args.get('category')
    
    query = {'is_active': True}
    if category:
        query['category'] = category
    
    keywords = list(db.suspicious_keywords.find(query).sort('keyword', 1))
    
    categories = db.suspicious_keywords.distinct('category', {'is_active': True})
    
    return render_template('admin/keywords_list.html',
                         keywords=keywords,
                         categories=categories,
                         selected_category=category)


@admin_bp.route('/keywords/add', methods=['GET', 'POST'])
def keywords_add():
    
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip().lower()
        category = request.form.get('category', 'action_words').strip()
        risk_level = request.form.get('risk_level', 'medium')
        
        if not keyword:
            flash('Keyword is required', 'error')
            return redirect(url_for('admin.keywords_add'))
        
        success = db.add_suspicious_keyword(keyword, category, risk_level)
        
        if success:
            flash(f'Successfully added keyword: {keyword}', 'success')
            return redirect(url_for('admin.keywords_list'))
        else:
            flash(f'Keyword {keyword} already exists', 'error')
    
    categories = db.suspicious_keywords.distinct('category', {'is_active': True})
    return render_template('admin/keywords_form.html', 
                         action='Add',
                         categories=categories)


@admin_bp.route('/keywords/delete/<keyword>', methods=['POST'])
def keywords_delete(keyword):
    
    success = db.delete_suspicious_keyword(keyword)
    
    if success:
        flash(f'Successfully deleted keyword: {keyword}', 'success')
    else:
        flash(f'Failed to delete keyword: {keyword}', 'error')
    
    return redirect(url_for('admin.keywords_list'))
    
#import function

def process_import_items(items, stats, *, required_field, lookup_collection, add_function, defaults=None):

    defaults = defaults or {}

    for item in items:
        try: 
            value = item.get(required_field)
            if not value:
                stats['errors'].append(f"Missing {required_field}")
                continue

            if lookup_collection.find_one({required_field: value.lower()}):
                stats['skipped'] += 1
                continue

            insert_data = {**defaults, **item}

            success = add_function(**insert_data)
            if success:
                stats['added'] += 1 
            else:
                stats['skipped'] += 1

        except Exception as e:
            stats['erros'].append(f"Error with {required_field} '{item.get(required_field, 'unknown')}': {e}")


@admin_bp.route('/import', methods=['GET', 'POST'])
def import_data():
    if request.method == 'POST':
        
        if 'file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('admin.import_data'))

        file = request.files['file']

        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('admin.import_data'))

        if not file.filename.endswith('.json'):
            flash('Only JSON files are supported', 'error')
            return redirect(url_for('admin.import_data'))

        try:
            data = json.load(file)
           
            stats = {
                'tlds': {'added': 0, 'skipped': 0, 'errors': []},
                'brands': {'added': 0, 'skipped': 0, 'errors': []},
                'keywords': {'added': 0, 'skipped': 0, 'errors': []},
                'blacklist': {'added': 0, 'skipped': 0, 'errors': []}
            }

            if 'tlds' in data:
                process_import_items(
                    data['tlds'], stats['tlds'],
                    required_field='tld',
                    lookup_collection=db.suspicious_tlds,
                    add_function=db.add_suspicious_tld,
                    defaults={'risk_level': 'medium', 'reason': '', 'added_by': 'import'}
                )

            if 'brands' in data:
                process_import_items(
                    data['brands'], stats['brands'],
                    required_field='brand_name',
                    lookup_collection=db.brands,
                    add_function=db.add_brand,
                    defaults={'category': 'general', 'added_by': 'import'}
                )

            if 'keywords' in data:
                process_import_items(
                    data['keywords'], stats['keywords'],
                    required_field='keyword',
                    lookup_collection=db.suspicious_keywords,
                    add_function=db.add_suspicious_keyword,
                    defaults={'category': 'action_words', 'risk_level': 'medium'}
                )

            if 'blacklist' in data:
                process_import_items(
                    data['blacklist'], stats['blacklist'],
                    required_field='domain',
                    lookup_collection=db.blacklisted_domains,
                    add_function=db.add_blacklisted_domain,
                    defaults={'source': 'import', 'reason': '', 'added_by': 'import'}
                )

            total_added = sum(s['added'] for s in stats.values())
            total_skipped = sum(s['skipped'] for s in stats.values())
            total_errors = sum(len(s['errors']) for s in stats.values())

        
            if total_added > 0:
                added_details = []
                for category, s in stats.items():
                    if s['added'] > 0:
                        added_details.append(f"{s['added']} {category}")
                flash(f"✅ Successfully imported: {', '.join(added_details)}", "success")

            
            if total_skipped > 0:
                skipped_details = []
                for category, s in stats.items():
                    if s['skipped'] > 0:
                        skipped_details.append(f"{s['skipped']} {category}")
                flash(f"⚠️ Skipped duplicates: {', '.join(skipped_details)}", "warning")

            if total_errors > 0:
                flash(f"❌ {total_errors} errors occurred", "error")
               
                for category, s in stats.items():
                    for err in s['errors'][:5]:
                        flash(f"{category.upper()}: {err}", "error")

            if total_added == 0 and total_skipped > 0:
                flash('All items were duplicates - nothing new to import', 'warning')

            return redirect(url_for('admin.dashboard'))

        except json.JSONDecodeError as e:
            flash(f"Invalid JSON format: {e}", "error")
        except Exception as e:
            flash(f"Import failed: {e}", "error")

    return render_template('admin/import.html')

@admin_bp.route('/import/validate', methods=['POST'])
def validate_import():
   
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    try:
        data = json.load(file)
        
        validation = {
            'valid': True,
            'summary': {
                'tlds': {'total': 0, 'duplicates': 0, 'invalid': 0},
                'brands': {'total': 0, 'duplicates': 0, 'invalid': 0},
                'keywords': {'total': 0, 'duplicates': 0, 'invalid': 0},
                'blacklist': {'total': 0, 'duplicates': 0, 'invalid': 0}
            },
            'errors': []
        }
        
        if 'tlds' in data:
            validation['summary']['tlds']['total'] = len(data['tlds'])
            for item in data['tlds']:
                if not item.get('tld'):
                    validation['summary']['tlds']['invalid'] += 1
                    validation['errors'].append('TLD missing "tld" field')
                elif db.suspicious_tlds.find_one({'tld': item['tld'].lower()}):
                    validation['summary']['tlds']['duplicates'] += 1
        
    
        if 'brands' in data:
            validation['summary']['brands']['total'] = len(data['brands'])
            for item in data['brands']:
                if not item.get('brand_name'):
                    validation['summary']['brands']['invalid'] += 1
                    validation['errors'].append('Brand missing "brand_name" field')
                elif db.brands.find_one({'brand_name': item['brand_name'].lower()}):
                    validation['summary']['brands']['duplicates'] += 1
        
        
        if 'keywords' in data:
            validation['summary']['keywords']['total'] = len(data['keywords'])
            for item in data['keywords']:
                if not item.get('keyword'):
                    validation['summary']['keywords']['invalid'] += 1
                    validation['errors'].append('Keyword missing "keyword" field')
                elif db.suspicious_keywords.find_one({'keyword': item['keyword'].lower()}):
                    validation['summary']['keywords']['duplicates'] += 1
        
        # Validate Blacklist
        if 'blacklist' in data:
            validation['summary']['blacklist']['total'] = len(data['blacklist'])
            for item in data['blacklist']:
                if not item.get('domain'):
                    validation['summary']['blacklist']['invalid'] += 1
                    validation['errors'].append('Blacklist entry missing "domain" field')
                elif db.blacklisted_domains.find_one({'domain': item['domain'].lower()}):
                    validation['summary']['blacklist']['duplicates'] += 1
        
        return jsonify(validation)
        
    except json.JSONDecodeError:
        return jsonify({'valid': False, 'error': 'Invalid JSON format'}), 400
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500


@admin_bp.route('/export')
def export_data():
    """Export all data to JSON"""
    try:
        data = {
            'tlds': [],
            'brands': [],
            'keywords': [],
            'blacklist': [],
            'exported_at': datetime.now().isoformat()
        }
        
        for tld in db.suspicious_tlds.find({'is_active': True}):
            data['tlds'].append({
                'tld': tld['tld'],
                'risk_level': tld.get('risk_level', 'medium'),
                'reason': tld.get('reason', ''),
                'added_by': tld.get('added_by', 'system')
            })
        
        # Export brands
        for brand in db.brands.find({'is_active': True}):
            data['brands'].append({
                'brand_name': brand['brand_name'],
                'category': brand.get('category', 'general'),
                'added_by': brand.get('added_by', 'system')
            })
        
        # Export keywords
        for kw in db.suspicious_keywords.find({'is_active': True}):
            data['keywords'].append({
                'keyword': kw['keyword'],
                'category': kw.get('category', 'action_words'),
                'risk_level': kw.get('risk_level', 'medium')
            })
        
        # Export blacklist
        for domain in db.blacklisted_domains.find({'is_active': True}):
            data['blacklist'].append({
                'domain': domain['domain'],
                'source': domain.get('source', 'manual'),
                'reason': domain.get('reason', ''),
                'added_by': domain.get('added_by', 'system')
            })
        
        response = jsonify(data)
        response.headers['Content-Disposition'] = f'attachment; filename=security_scanner_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        return response
        
    except Exception as e:
        flash(f'Export failed: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))



@admin_bp.errorhandler(404)
def not_found(e):
    return render_template('admin/error.html', 
                         error_code=404, 
                         error_message='Page not found'), 404


@admin_bp.errorhandler(500)
def server_error(e):
    return render_template('admin/error.html',
                         error_code=500,
                         error_message='Internal server error'), 500



@admin_bp.teardown_app_request
def cleanup(exception=None):
    pass
