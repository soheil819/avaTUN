"""Native Telegram screens. Presentation has no panel or network side effects."""
import html
import re
import unicodedata


def digits(value):
    result = []
    for char in str(value):
        try:
            result.append(str(unicodedata.decimal(char)))
        except (ValueError, TypeError):
            result.append(char)
    return ''.join(result)


def escape(value, limit=180):
    value = digits(value)
    if len(value) > limit:
        value = value[:limit-1] + '…'
    return html.escape(value, quote=False)


def detail(value):
    value = digits(value)
    if len(value)>140:value=value[:139]+'…'
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?(?::[0-9]{1,5})?\b'
    parts=[]; previous=0
    for match in re.finditer(pattern,value):
        parts.extend([html.escape(value[previous:match.start()],quote=False),
                      '<code>'+html.escape(match[0],quote=False)+'</code>'])
        previous=match.end()
    parts.append(html.escape(value[previous:],quote=False))
    return ''.join(parts)


PAGES = {
    'overview':'خانه', 'servers':'سرورها', 'server':'جزئیات سرور',
    'tunnels':'تونل‌ها', 'tunnel':'جزئیات تونل', 'resources':'منابع',
    'forward_servers':'انتخاب سرور', 'forwards':'فوروارد', 'forward':'جزئیات قانون',
    'report':'گزارش', 'audit':'عملیات اخیر', 'update':'به‌روزرسانی',
    'settings':'تنظیمات ربات', 'help':'راهنما', 'confirm':'تأیید عملیات', 'job':'نتیجهٔ عملیات',
}


def context(state):
    return {'page':state.get('page','overview'), 'page_index':state.get('p',0),
            'server_id':state.get('server_id','all'), 'selected':state.get('selected','')}


def render(state, button):
    """Return one HTML message and its contextual inline keyboard."""
    page = state.get('page','overview')
    ctx = context(state)
    def nav(label, query, target=None):
        return button(digits(label), 'navigate', query=query, context=target or ctx)
    title = state.get('title') or PAGES.get(page,'avaTUN')
    lines = ['<b>'+escape(title,90)+'</b>']
    if page != 'overview':
        section = {'server':'سرورها','tunnel':'تونل‌ها','forward':'فوروارد'}.get(page)
        lines.append('avaTUN / '+escape(section or PAGES.get(page,'مدیریت')))
    if state.get('summary'):
        lines.extend(['',escape(state['summary'])])
    rows = state.get('rows') or []
    keyboard = []
    for index, item in enumerate(rows):
        marker = {'up':'🟢','down':'🔴','error':'🔴','unknown':'⚪','monitor-only':'🟡'}.get(item.get('state'),'')
        label = str(item.get('title',''))
        lines.extend(['', f'{marker} <b>{escape(label,80)}</b>'.strip()])
        for line in item.get('lines',[])[:4]:
            # Separate endpoints and addresses from surrounding RTL text.
            lines.append(detail(line))
        if item.get('badge'):
            lines.append('<i>'+escape(item['badge'],50)+'</i>')
        if item.get('query'):
            keyboard.append([nav((marker+' ' if marker else '')+label, item['query'])])
    if not rows and page in ('servers','tunnels','resources','forwards','audit'):
        lines.extend(['', {'tunnels':'تونلی در این بخش ثبت نشده است.',
                         'forwards':'هنوز قانونی برای این سرور ثبت نشده است.',
                         'resources':'نمونهٔ منابع در دسترس نیست؛ وضعیت اتصال سرور را بررسی کن.',
                         'audit':'هنوز عملیاتی ثبت نشده است.'}.get(page,'موردی برای نمایش وجود ندارد.')])
    if state.get('message'):
        lines.extend(['',escape(state['message'],550)])

    if page == 'overview':
        keyboard = [
            [nav('سرورها','nav:servers'),nav('تونل‌ها','nav:tunnels')],
            [nav('منابع','nav:resources'),nav('گزارش 24 ساعت','nav:report')],
        ]
        if state.get('role') == 'admin':
            keyboard += [[nav('فوروارد','nav:forward_servers'),nav('به‌روزرسانی','nav:update')],
                         [nav('عملیات اخیر','nav:audit'),nav('تنظیمات و راهنما','nav:settings')]]
        else:
            keyboard += [[nav('راهنما','nav:help')]]
    else:
        actions = [a for a in state.get('actions',[]) if a.get('query') not in
                   ('refresh','nav:servers','nav:tunnels','nav:forwards') and
                   not a.get('query','').startswith('refresh:')]
        for index in range(0,len(actions),2):
            keyboard.append([nav(a['label'],a['query']) for a in actions[index:index+2]])
    total = int(state.get('n',1)); current = int(state.get('p',0))
    if total > 1:
        lines.extend(['',f'صفحهٔ {current+1} از {total}'])
        paging = []
        if current > 0: paging.append(nav('‹ قبلی',f'page:{page}:{current-1}'))
        if current+1 < total: paging.append(nav('بعدی ›',f'page:{page}:{current+1}'))
        keyboard.append(paging)
    if state.get('updated'):
        lines.extend(['','<i>آخرین دریافت: '+escape(state['updated'],30)+'</i>'])
    if page != 'overview':
        back = {'server':'nav:servers','tunnel':'nav:tunnels','forward':'nav:forwards',
                'forwards':'nav:forward_servers','help':'nav:settings'}.get(page,'nav:overview')
        keyboard.append([nav('بازگشت',back),nav('خانه','nav:overview')])
    if page not in ('confirm','help','settings','job'):
        keyboard.append([nav('↻ تازه‌سازی','refresh')])
    return '\n'.join(lines), keyboard
