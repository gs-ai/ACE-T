// assets/clientside.js
window.dash_clientside = Object.assign({}, window.dash_clientside, {
  clientside: {
    cy_fit: function(nClicks) {
      if (!nClicks) return window.dash_clientside.no_update;
      const cy = window._dashCytoscape && window._dashCytoscape.get && window._dashCytoscape.get('cy');
      if (cy && cy.fit) {
        try { cy.fit(undefined, 50); } catch (e) {}
      }
      return window.dash_clientside.no_update;
    }
  }
});