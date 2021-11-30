import Ora from "ora";
import Loki from "lokijs";
import Snoowrap from "snoowrap";

export default class Bot {
	// Config objects
	#config; #lokiConfig;
	// Context variables
	#client; #spinner; #db;
	// Polling variables
	#pollInterval; #pollRate;

	constructor(config = {}) {
		// Sanitize inputs
		this.#pollRate = Math.max(5_000, 1_000 * (60 / (config.rpm || 10_000)));

		// Init
		this.#spinner = new Ora({ spinner: 'earth' });
		this.#spinner.start('Firing up Reddit bot');

		// Snoowrap config
		this.#config = config.snoowrap;

		try {
			this.#client = new Snoowrap({
				username: this.#config.username,
				userAgent: this.#config.userAgent,
				clientId: this.#config.clientId,
				clientSecret: this.#config.clientSecret,
				password: this.#config.password
			});

			this.#spinner.succeed('Successfully started bot')
		} catch (error) {
			this.#spinner.fail(`[BOT_ERROR] Unable to start bot: ${error.message}`);

			return
		};

		// Start the update loop
		try {
			this.#spinner.spinner = 'arc';
			this.#spinner.start('[LOKI_DB] Initializing database');
			this.#lokiConfig = config.loki;

			// LokiDb config
			this.#db = new Loki(this.#lokiConfig.path, {
				autoload: this.#lokiConfig.autoload,
				autosave: this.#lokiConfig.autosave,
				autosaveInterval: this.#lokiConfig.autosaveInterval,
				autoloadCallback: () => {
					let replies = this.#db.getCollection('replies');
					if (replies === null) {
						this.#spinner.spinner = 'grenade';
						this.#spinner.start('[LOKI_DB] Adding users Collection')
						replies = this.#db.addCollection('replies', { unique: ['contentId'] });
					};

					// Inform of success
					this.#spinner.succeed('[LOKI_DB] Successfully initialized database');

					// Check for mentions and messages
					this.#spinner.spinner = 'earth';
					this.#spinner.start(`Checking for mentions and messages: ${Math.round(1_000_000 / this.#pollRate) / 1_000}Hz`);

					// Start polling for updates
					this.#pollInterval = setInterval(() => {
						this.poll(replies).catch(err => {
							clearInterval(this.#pollInterval);
							this.#spinner.fail(`[BOT_POLL_ERROR]: ${err}`);
						})
					}, this.#pollRate)
				}
			});
		} catch (error) {
			this.#spinner.fail(`[BOT_ERROR] ${error.message}`)
		}
	}

	async poll(replies) {
		let mentions = await this.#client.getInbox({ filter: 'unread' });

		// Can't handle mentions if they do not exist
		if (!mentions.length > 0) { return };

		// Handle mentions
		for (let i = 0; i < mentions.length; i++) {
			const mention = mentions[i], tag = `u/${this.#config.username}`, regex = new RegExp(`u\/${this.#config.username}.*$`, `gm`);

			// Only replies to comments where mentioned
			if (!mention.was_comment && mention.body.includes(tag)) continue;

			const finds = replies.find({ contentId: mention.id });

			// This mention has been replied to before
			if (finds.length > 0) continue;

			// reply to mention and update database
			const match = regex.exec(mention.body);
			this.reply(mention, match[0]);
			replies.insert({ contentId: mention.id });
			this.#db.save();
		};

		this.#spinner.spinner = 'earth';
		this.#spinner.start(`Checking for mention: ${Math.round(1_000_000 / this.#pollRate) / 1_000}Hz`);
	}

	reply(mention, query) {
		this.#spinner.info(`[BOT] Replying to mention (${mention.id}), author (${mention.author.name})`)
	}
}