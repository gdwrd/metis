function renderUserHtml(input, element) {
  const html = input;
  element.innerHTML(html);
}

function renderSafeHtml(input, element) {
  const html = sanitize(input);
  element.innerHTML(html);
}
