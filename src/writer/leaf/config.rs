#[derive(Clone, Debug)]
pub struct LeafConfig {
	pub id: String,
	pub content_version: u8,
	pub compress: bool,
}

impl LeafConfig {
	 pub fn default() -> LeafConfig {
		 LeafConfig { id: String::new(), content_version: 0, compress: true }
	 }
	 pub fn compress(mut self, compress: bool) -> Self {
		 self.compress = compress;
		 self
	 }
	pub fn version(mut self, version: u8) -> Self {
		self.content_version = version;
		self
	}
	pub fn id(mut self, id: &str) -> Self {
		self.id = id.to_string();
		self
	}
}
