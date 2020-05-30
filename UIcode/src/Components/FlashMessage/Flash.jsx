class Flash {
  constructor() {
    this.state = {};
  }

  get() {
    return this.state;
  }

  set(message, type = "info") {
    this.state = { message, type };
  }
}

export default new Flash();
