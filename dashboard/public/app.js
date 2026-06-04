const { createApp } = Vue;

createApp({
  data() {
    return {
      nodes: [],
      events: [],
      summary: { byType: {}, alerts: [] },
      loading: false,
      lastUpdated: "not yet refreshed"
    };
  },
  mounted() {
    this.refreshData();
    setInterval(this.refreshData, 5000);
  },
  methods: {
    async refreshData() {
      this.loading = true;
      const [nodes, events, summary] = await Promise.all([
        fetch("/api/nodes").then((response) => response.json()),
        fetch("/api/events").then((response) => response.json()),
        fetch("/api/summary").then((response) => response.json())
      ]);

      this.nodes = nodes;
      this.events = events;
      this.summary = summary;
      this.lastUpdated = new Date().toLocaleTimeString("zh-TW", { hour12: false });
      this.loading = false;
    },
    formatTime(value) {
      if (!value) return "";
      return new Date(value).toLocaleTimeString("zh-TW", { hour12: false });
    }
  }
}).mount("#app");
