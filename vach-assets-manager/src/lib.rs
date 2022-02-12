use std::borrow::Cow;
use std::fs::File;
use assets_manager::source::{DirEntry, Source};
use parking_lot::Mutex;
use ahash::AHashMap;
use vach::prelude::*;

// TODO:
// - Support 'folders' in archives (such as data.vach/music/ambient.flac, where music/ambient.vach is the file name in the archive)

pub struct ArchiveSource {
	// The key is the archive location relative to the base
	// the key has '/' replaced with '.', and the file extension removed
	archives: AHashMap<String, Mutex<Archive<File>>>,
}

impl ArchiveSource {
	/// path: the base path to start looking for archives
	/// ext: the extensions that archives have,
	/// if left empty the '.vach' extension is the only one assumed to be used, and archives without the `.vach` extension will be ignored
	/// multiple extensions can be used here:
	/// ```rust
	/// use vach_assets_manager::ArchiveSource;
	/// let source = ArchiveSource::new("assets", &[]); // here, '.vach' is assumed to be the extension used for archives
	/// ```
	/// ```rust
	/// use vach_assets_manager::ArchiveSource;
	/// let source = ArchiveSource::new("assets", &["pak", "pkg"]); // here, files with the '.pak' and '.pkg' extensions are attempted to be loaded as archives
	/// ```
	pub fn new(path: &str, ext: &[&str]) -> InternalResult<Self> {
		Self::new_with_header_config(path, ext, &HeaderConfig::default())
	}

	pub fn new_with_header_config(base_path: &str, ext: &[&str], header_config: &HeaderConfig) -> InternalResult<Self> {
		let extensions = match ext.len() {
			0 => vec!["vach"],
			_ => {
				let mut new_ext = vec!["vach"];
				new_ext.copy_from_slice(&ext);
				new_ext
			},
		};

		let mut archives = AHashMap::new();

		for entry in walkdir::WalkDir::new(base_path) {
			match entry {
				Ok(entry) => {
					let abs_path = entry.path().to_string_lossy().to_string();

					if !match entry.metadata() {
						Ok(metadata) => metadata.is_file(),
						Err(e) => {
							log::warn!("Unable to read metadata for file/folder {}: {}", &abs_path, e);
							continue;
						},
					} {
						// not a file, skip
						continue;
					}

					let path_ext = abs_path.split('.').last().unwrap_or("");
					if !extensions.iter().any(|ext| &path_ext == ext) {
						// archive does not have one of the specified extensions
						log::trace!("Skipping file {}, reason: ignored file extension", &abs_path);
						continue;
					}

					let relative_path = match pathdiff::diff_paths(entry.path(), base_path) {
						Some(p) => p,
						None => {
							log::warn!(
								"Failed to make path relative, skipping '{}'. (base path: '{}')",
								&abs_path,
								base_path
							);
							continue;
						},
					};

					log::trace!("Opening archive {}", &abs_path);
					let handle = match File::open(&abs_path) {
						Ok(handle) => handle,
						Err(e) => {
							log::warn!("Failed to open file {}, skipping: {}", &abs_path, e);
							continue;
						},
					};

					// maybe using a bufreader is faster?
					let archive = match Archive::with_config(handle, header_config) {
						Ok(archive) => archive,
						Err(e) => {
							log::warn!("Loading archive {} failed, skipping: {}", &abs_path, e);
							continue;
						},
					};

					let relative_path_string = relative_path.to_string_lossy().to_string();
					let relative_path_without_extension = split_collect_all_except_last(&relative_path_string, '.');

					archives.insert(
						relative_path_without_extension.replace("/", ".").replace("\\", "."),
						Mutex::new(archive),
					);
				},
				Err(e) => log::warn!("Unable to read folder/file: {}", e),
			}
		}

		log::trace!("Listing loaded archives: ");
		let _ = archives
			.keys()
			.map(|val| {
				log::trace!("{}", val);
			})
			.collect::<()>();

		Ok(Self { archives })
	}
}

#[test]
fn test() {
	env_logger::init();
	let source = ArchiveSource::new("./", &["pak", "pkg"]).unwrap();
	let cache = assets_manager::AssetCache::with_source(source);
	let song_1 = cache.load::<String>("test-data.music.song").unwrap();
	let song_2 = cache.load::<String>("test-data.music.data.song").unwrap();
	assert_eq!(song_1, song_2);

	let poem_1 = cache.load::<String>("test-data.music.poem").unwrap();
	let poem_2 = cache.load::<String>("test-data.music.data.poem").unwrap();
	assert_eq!(poem_1, poem_2);

	let lorem_1 = cache.load::<String>("test-data.music.lorem").unwrap();
	let lorem_2 = cache.load::<String>("test-data.music.data.lorem").unwrap();
	assert_eq!(lorem_1, lorem_2);
}

impl Source for ArchiveSource {
	fn read(&self, id: &str, ext: &str) -> std::io::Result<Cow<[u8]>> {
		let (archive_name, file_name) = id_and_extension_to_file_archive_name(id, ext);

		let archive = match self.archives.get(&archive_name) {
			Some(archive) => archive,
			None => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::NotFound,
					format!("Archive '{}' not found", archive_name),
				))
			},
		};

		let mut lock = archive.lock();
		match lock.fetch(&file_name) {
			Ok(entry) => Ok(Cow::from(entry.data)),
			Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
		}
	}

	fn read_dir(&self, id: &str, f: &mut dyn FnMut(DirEntry)) -> std::io::Result<()> {
		Ok(self
			.archives
			.keys()
			.filter(|val| val.starts_with(id))
			.map(|val| {
				let id = split_collect_all_except_last(val, '.');
				let mut ext = val.replace(&id, "");
				ext = ext.replace(".", "");

				f(DirEntry::File(&id, &ext));
			})
			.collect::<()>())
	}

	fn exists(&self, entry: DirEntry) -> bool {
		match entry {
			DirEntry::File(id, ext) => {
				let (archive_name, file_name) = id_and_extension_to_file_archive_name(id, ext);

				let archive = match self.archives.get(&archive_name) {
					Some(archive) => archive,
					None => return false,
				};

				let lock = archive.lock();
				lock.entries().contains_key(&file_name)
			},
			DirEntry::Directory(path) => self.archives.keys().any(|val| val.starts_with(path)),
		}
	}
}

fn split_collect_all_except_last(string: &str, split: char) -> String {
	let mut result = string.split(split).collect::<Vec<&str>>();
	match result.len() {
		0 => return String::new(),
		1 => return result[0].to_string(),
		2 => return result[0].to_string(),
		_ => (),
	}

	// guaranteed to never panic, since the array is guaranteed to be more than 2 elements long
	result.pop().unwrap();
	let last_item = result.pop().unwrap();

	// append `split` after each item in the array
	let mut string = result
		.iter()
		.map(|val| val.to_string())
		.map(|mut val| {
			val.push(split);
			val
		})
		.collect::<String>();

	// push back the last item, since we don't want `split` to be appended after the final item
	string.push_str(last_item);
	string
}

fn id_and_extension_to_file_archive_name(id: &str, ext: &str) -> (String, String) {
	let file_name = format!("{}.{}", id.split('.').last().unwrap_or(id), ext);
	let archive_name = split_collect_all_except_last(id, '.');
	(archive_name, file_name)
}

#[test]
fn test_id_and_extension_to_file_archive_name() {
	assert_eq!(
		id_and_extension_to_file_archive_name("music.ambient", "flac"),
		("music".to_string(), "ambient.flac".to_string())
	);

	assert_eq!(
		id_and_extension_to_file_archive_name("music.forest.ambient", "wav"),
		("music.forest".to_string(), "ambient.wav".to_string())
	);

	assert_eq!(
		id_and_extension_to_file_archive_name("shared.music.forest.ambient", "wav"),
		("shared.music.forest".to_string(), "ambient.wav".to_string())
	);
}
