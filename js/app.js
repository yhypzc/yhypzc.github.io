// SPA Router - single-page blog engine
(function() {
  var siteTitle = document.querySelector("meta[name=blog-title]").content;
  var posts = [];
  var currentView = null;

  function loadManifest(cb) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", getRoot() + "posts.json", true);
    xhr.onload = function() {
      if (xhr.status === 200) {
        try { posts = JSON.parse(xhr.responseText); } catch(e) {}
      }
      cb();
    };
    xhr.onerror = function() { cb(); };
    xhr.send();
  }

  function getRoot() {
    var p = window.location.pathname;
    if (p.indexOf("/posts/") >= 0) return "/";
    return "./";
  }

  function getSlugFromPath() {
    var p = window.location.pathname;
    var m = p.match(/\/posts\/([^\/]+)/);
    return m ? decodeURIComponent(m[1]) : null;
  }

  // Force UTF-8 fetch for .md files (GitHub Pages may not set charset)
  function fetchMarkdown(url, cb) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, true);
    xhr.responseType = "arraybuffer";
    xhr.onload = function() {
      if (xhr.status === 200) {
        var decoder = new TextDecoder("utf-8");
        var text = decoder.decode(new Uint8Array(xhr.response));
        cb(null, text);
      } else {
        cb(new Error("HTTP " + xhr.status));
      }
    };
    xhr.onerror = function() { cb(new Error("Network error")); };
    xhr.send();
  }

  // Ensure blank lines before code fences for proper parsing
  function normalizeMarkdown(text) {
    // 1. Normalize line endings (CRLF -> LF)
    text = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    // 2. Decode \xHH byte escape sequences to actual UTF-8
    text = text.replace(/\\x([0-9a-fA-F]{2})/g, function(m, h) {
      return String.fromCharCode(parseInt(h, 16));
    });
    // 3. Strip frontmatter
    if (text.startsWith("---")) {
      var parts = text.split("\n---\n", 2);
      if (parts.length >= 2) text = parts[1];
      else {
        parts = text.split("---", 3);
        text = parts.length >= 3 ? parts[2] : text;
      }
    }
    // 4. Strip leading whitespace from fence lines (marked.js requires no indent)
    text = text.replace(/^(\s*)(```)/gm, "```");
    // 5. Ensure blank line before opening fences
    text = text.replace(/\n(```)/g, "\n\n$1");
    if (text.startsWith("```")) text = "\n" + text;
    return text;
  }

  function renderList() {
    currentView = "list";
    document.title = siteTitle;
    var container = document.getElementById("blog-list");
    var postView = document.getElementById("post-view");
    container.style.display = "block";
    postView.style.display = "none";
    if (posts.length === 0) {
      container.innerHTML = '<div class="page-header"><h1 class="page-title">Blog</h1></div><div class="empty-state"><p>暂无文章</p></div>';
      return;
    }
    var desc = (document.querySelector("meta[name=blog-desc]")||{}).content||"";
    var cards = "";
    for (var i = 0; i < posts.length; i++) {
      cards += renderCard(posts[i], i);
    }
    container.innerHTML = '<div class="page-header"><h1 class="page-title">Blog</h1><p class="page-subtitle">' + desc + '</p></div><div class="post-list">' + cards + '</div>';
    window.scrollTo(0, 0);
  }

  function renderCard(p, i) {
    var root = getRoot();
    var url = root + "posts/" + p.slug + "/";
    var pin = p.pinned ? '<iconify-icon class="pin-icon" icon="mdi:pin"></iconify-icon>' : "";
    var cat = p.category ? '<span class="meta-item with-divider"><iconify-icon class="meta-icon" icon="material-symbols:folder-outline-rounded"></iconify-icon>' + p.category + '</span>' : "";
    var desc = p.description ? '<p class="post-card-desc">' + p.description + '</p>' : "";
    var tags = "";
    if (p.tags) {
      tags = '<div class="post-card-tags">';
      for (var t = 0; t < p.tags.length; t++) tags += '<a href="' + root + 'archive.html" class="tag-chip"># ' + p.tags[t] + '</a>';
      tags += '</div>';
    }
    var cover = "", enter = "";
    if (p.image) {
      cover = '<a href="' + url + '" class="post-card-cover"><img src="posts/' + p.slug + '/' + p.image + '" alt="" loading="lazy"><div class="post-card-cover-overlay"><iconify-icon icon="material-symbols:chevron-right-rounded"></iconify-icon></div></a>';
    } else {
      enter = '<a href="' + url + '" class="post-card-enter-btn"><iconify-icon icon="material-symbols:chevron-right-rounded"></iconify-icon></a>';
    }
    return '<article class="post-card card-base onload-animation" style="--i:' + i + ';--interval:50ms"><div class="post-card-body"><a href="' + url + '" class="post-card-title">' + pin + escHtml(p.title) + '<iconify-icon class="post-card-arrow" icon="material-symbols:chevron-right-rounded"></iconify-icon></a><div class="post-card-meta"><span class="meta-item"><iconify-icon class="meta-icon" icon="material-symbols:calendar-today-outline-rounded"></iconify-icon><time datetime="' + p.published + '">' + p.published + '</time></span>' + cat + '<span class="meta-item"><iconify-icon class="meta-icon" icon="material-symbols:timer-outline"></iconify-icon>' + p.words + ' 字</span></div>' + desc + tags + '</div>' + cover + enter + '</article>';
  }

  function escHtml(s) {
    return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function renderPost(slug) {
    var post = null;
    for (var i = 0; i < posts.length; i++) {
      if (posts[i].slug === slug) { post = posts[i]; break; }
    }
    if (!post) { renderList(); return; }
    currentView = "post";
    document.title = post.title + " - " + siteTitle;
    var container = document.getElementById("blog-list");
    var postView = document.getElementById("post-view");
    container.style.display = "none";
    postView.style.display = "block";

    var up = post.updated ? '<span class="meta-item with-divider"><iconify-icon class="meta-icon" icon="material-symbols:update-rounded"></iconify-icon>更新于 ' + post.updated + '</span>' : "";
    var cat = post.category ? '<span class="meta-item with-divider"><iconify-icon class="meta-icon" icon="material-symbols:folder-outline-rounded"></iconify-icon>' + post.category + '</span>' : "";
    var tags = "";
    if (post.tags) {
      tags = '<div class="post-page-tags">';
      for (var t = 0; t < post.tags.length; t++) tags += '<a href="' + getRoot() + 'archive.html" class="tag-chip"># ' + post.tags[t] + '</a>';
      tags += '</div>';
    }
    var cover = post.image ? '<div class="post-page-cover"><img src="' + post.image + '" alt="" loading="lazy"></div>' : "";

    var idx = -1;
    for (var i = 0; i < posts.length; i++) { if (posts[i].slug === slug) { idx = i; break; } }
    var prev = idx > 0 ? posts[idx-1] : null;
    var next = idx < posts.length-1 ? posts[idx+1] : null;
    var nav = "";
    if (prev || next) {
      nav = '<nav class="post-navigation">';
      if (prev) nav += '<a href="' + getRoot() + 'posts/' + prev.slug + '/" class="post-nav post-nav-prev"><span class="nav-label">上一页</span><span class="nav-title">' + escHtml(prev.title) + '</span></a>';
      if (next) nav += '<a href="' + getRoot() + 'posts/' + next.slug + '/" class="post-nav post-nav-next"><span class="nav-label">下一页</span><span class="nav-title">' + escHtml(next.title) + '</span></a>';
      nav += '</nav>';
    }

    postView.innerHTML = '<article class="post-page card-base"><div class="post-page-header"><h1 class="post-page-title">' + escHtml(post.title) + '</h1><div class="post-page-meta"><span class="meta-item"><iconify-icon class="meta-icon" icon="material-symbols:calendar-today-outline-rounded"></iconify-icon><time datetime="' + post.published + '">' + post.published + '</time></span>' + up + cat + '<span class="meta-item"><iconify-icon class="meta-icon" icon="material-symbols:timer-outline"></iconify-icon>' + post.words + ' 字</span></div>' + tags + '</div>' + cover + '<div class="post-page-content custom-md" id="post-content"><p>Loading...</p></div>' + nav + '</article>';

    var mdUrl = getRoot() + "posts/" + slug + "/" + post.md_filename;
    fetchMarkdown(mdUrl, function(err, text) {
      if (err) {
        document.getElementById("post-content").innerHTML = "<p>Failed to load: " + err.message + "</p>";
        return;
      }
      var html = marked.parse(normalizeMarkdown(text));
      document.getElementById("post-content").innerHTML = html;
      var imgs = document.getElementById("post-content").querySelectorAll("img");
      var postBase = getRoot() + "posts/" + slug + "/";
      imgs.forEach(function(img) {
        var s = img.getAttribute("src") || "";
        if (s && !s.startsWith("http") && !s.startsWith("/") && !s.startsWith("data:")) {
          img.src = postBase + s;
        }
        img.onerror = function() { this.style.display = "none"; };
      });
    });

    window.scrollTo(0, 0);
  }

  function handleNav(e) {
    var a = e.target.closest("a");
    if (!a) return;
    var href = a.getAttribute("href");
    if (!href) return;
    var m = href.match(/posts\/([^\/]+)\/?$/);
    if (m && !href.startsWith("http")) {
      e.preventDefault();
      var slug = decodeURIComponent(m[1]);
      renderPost(slug);
      if (history.pushState) {
        history.pushState({slug:slug}, "", href);
      }
    }
  }

  window.addEventListener("popstate", function(e) {
    var slug = getSlugFromPath();
    if (slug) renderPost(slug);
    else renderList();
  });

  loadManifest(function() {
    var slug = getSlugFromPath();
    document.addEventListener("click", handleNav);
    if (slug) {
      renderPost(slug);
      if (history.replaceState) {
        history.replaceState({slug:slug}, "", window.location.pathname);
      }
    } else {
      renderList();
    }
  });
})();
