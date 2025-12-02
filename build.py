import os
import shutil
import re
import datetime
import glob

# Configuration
SITE_NAME = "CyberSec Blog"
USER_NAME = "effect" # Placeholder, will be updated
OUTPUT_DIR = "docs"
CONTENT_DIR = "content"
TEMPLATE_PATH = "src/template.html"
STYLE_PATH = "src/style.css"

def parse_markdown(text):
    """
    A simple Markdown parser.
    Supports: headers, bold, italic, links, code blocks, lists, paragraphs.
    """
    html = text

    # Escape HTML characters to prevent injection (basic)
    # html = html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") 
    # Note: We trust the user's input for now to allow embedding HTML if needed, 
    # but for a real parser we should be careful. 
    # For this simple script, we'll assume the user writes valid MD.

    # Code blocks (```code```)
    # We use a placeholder to prevent other regexes from messing with code blocks
    code_blocks = {}
    def save_code_block(match):
        key = f"CODEBLOCK_{len(code_blocks)}"
        code_blocks[key] = f"<pre><code>{match.group(1)}</code></pre>"
        return key
    
    html = re.sub(r'```(.*?)```', save_code_block, html, flags=re.DOTALL)

    # Headers
    html = re.sub(r'^# (.*$)', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*$)', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^### (.*$)', r'<h3>\1</h3>', html, flags=re.MULTILINE)

    # Bold
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    
    # Italic
    html = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html)

    # Links [text](url)
    html = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', html)

    # Unordered Lists
    def parse_list(match):
        items = match.group(0).strip().split('\n')
        list_html = "<ul>\n"
        for item in items:
            list_html += f"<li>{item[2:]}</li>\n"
        list_html += "</ul>"
        return list_html

    html = re.sub(r'(?:^-\s.*(?:\n|$))+', parse_list, html, flags=re.MULTILINE)

    # Paragraphs
    # Split by double newlines and wrap in <p> if not already an HTML tag
    lines = html.split('\n\n')
    new_lines = []
    for line in lines:
        line = line.strip()
        if not line: continue
        if line.startswith('<') and not line.startswith('<a') and not line.startswith('<strong') and not line.startswith('<em'):
             new_lines.append(line)
        elif line.startswith('CODEBLOCK_'):
             new_lines.append(line)
        else:
            new_lines.append(f"<p>{line}</p>")
    
    html = '\n'.join(new_lines)

    # Restore code blocks
    for key, value in code_blocks.items():
        html = html.replace(key, value)

    return html

def parse_front_matter(content):
    """
    Parses YAML-like front matter.
    ---
    title: Hello
    date: 2023-01-01
    ---
    """
    meta = {}
    body = content
    if content.startswith('---'):
        parts = content.split('---', 2)
        if len(parts) >= 3:
            front_matter = parts[1]
            body = parts[2]
            for line in front_matter.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    meta[key.strip()] = value.strip()
    return meta, body.strip()

def render_template(template, context):
    output = template
    for key, value in context.items():
        output = output.replace(f"{{{{ {key} }}}}", str(value))
    return output

def build():
    # 1. Clean output dir
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    os.makedirs(os.path.join(OUTPUT_DIR, "writeups"))
    os.makedirs(os.path.join(OUTPUT_DIR, "assets"))

    # 2. Copy assets
    shutil.copy(STYLE_PATH, os.path.join(OUTPUT_DIR, "style.css"))
    # Copy images if any
    for img in glob.glob("src/assets/*"):
        shutil.copy(img, os.path.join(OUTPUT_DIR, "assets", os.path.basename(img)))

    # 3. Read template
    with open(TEMPLATE_PATH, 'r') as f:
        template = f.read()

    # 4. Generate Home Page
    home_content = """
    <div class="profile">
        <img src="assets/profile.jpg" alt="Profile Picture" class="profile-img">
        <h1>Hello, I'm Effect</h1>
        <div class="subtitle">Cybersecurity Student</div>
        <p>Welcome to my digital garden. Here I share my journey, writeups, and research in the world of cybersecurity.</p>
        <div class="social-links">
            <a href="https://github.com/eff4ctt" target="_blank" title="GitHub">
                <img src="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/github.svg" alt="GitHub">
            </a>
            <a href="https://app.hackthebox.com/users/2119866" target="_blank" title="HackTheBox">
                <img src="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/hackthebox.svg" alt="HackTheBox">
            </a>
            <a href="https://www.root-me.org/eff4ct" target="_blank" title="RootMe">
                <img src="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/rootme.svg" alt="RootMe">
            </a>
            <a href="https://discord.com/users/1036382622202482728" target="_blank" title="Discord">
                <img src="https://cdn.jsdelivr.net/npm/simple-icons@v10/icons/discord.svg" alt="Discord">
            </a>
        </div>
    </div>
    """
    
    home_html = render_template(template, {
        "title": "Home",
        "site_name": SITE_NAME,
        "description": "Cybersecurity student portfolio and blog.",
        "user_name": USER_NAME,
        "active_home": "active",
        "active_writeups": "",
        "content": home_content,
        "year": datetime.datetime.now().year,
        "root_path": "."
    })

    with open(os.path.join(OUTPUT_DIR, "index.html"), 'w') as f:
        f.write(home_html)

    # 5. Generate Writeups
    writeups = []
    writeup_files = glob.glob(os.path.join(CONTENT_DIR, "writeups", "*.md"))
    
    for file_path in writeup_files:
        with open(file_path, 'r') as f:
            content = f.read()
        
        meta, body = parse_front_matter(content)
        html_body = parse_markdown(body)
        slug = os.path.basename(file_path).replace('.md', '')
        
        # Writeup Page
        writeup_html = render_template(template, {
            "title": meta.get('title', 'Untitled'),
            "site_name": SITE_NAME,
            "description": meta.get('description', ''),
            "user_name": USER_NAME,
            "active_home": "",
            "active_writeups": "active",
            "content": f"<div class='content'><h1>{meta.get('title')}</h1><p class='writeup-meta'>{meta.get('date', '')}</p>{html_body}</div>",
            "year": datetime.datetime.now().year,
            "root_path": ".."
        })
        
        with open(os.path.join(OUTPUT_DIR, "writeups", f"{slug}.html"), 'w') as f:
            f.write(writeup_html)
            
        writeups.append({
            "title": meta.get('title', 'Untitled'),
            "date": meta.get('date', ''),
            "description": meta.get('description', ''),
            "slug": slug
        })

    # 6. Generate Writeups Index
    writeups_list_html = "<div class='content'><h1>Writeups</h1><ul class='writeup-list'>"
    for w in sorted(writeups, key=lambda x: x['date'], reverse=True):
        writeups_list_html += f"""
        <li class='writeup-card'>
            <h2><a href="{w['slug']}.html">{w['title']}</a></h2>
            <div class='writeup-meta'>{w['date']}</div>
            <p class='writeup-excerpt'>{w['description']}</p>
        </li>
        """
    writeups_list_html += "</ul></div>"

    writeups_index_html = render_template(template, {
        "title": "Writeups",
        "site_name": SITE_NAME,
        "description": "List of cybersecurity writeups.",
        "user_name": USER_NAME,
        "active_home": "",
        "active_writeups": "active",
        "content": writeups_list_html,
        "year": datetime.datetime.now().year,
        "root_path": ".."
    })

    with open(os.path.join(OUTPUT_DIR, "writeups", "index.html"), 'w') as f:
        f.write(writeups_index_html)

    print(f"Build complete! Output in {OUTPUT_DIR}/")

if __name__ == "__main__":
    build()
