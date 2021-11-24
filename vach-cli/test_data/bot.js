import Ora from "ora";
import Loki from "lokijs";
import Snoowrap from "snoowrap";

export default class Bot {
	#snoowrap; #loki;
	#r; #spinner; #updateInterval; #rate;
	// Database stores replied to comments, messages
	#db;

	constructor(config = {}) {
		// Sanitize inputs
		this.#rate = Math.max(5_000, 1_000 * (60 / (config.rpm || 10_000)));

		// Init
		this.#spinner = new Ora({ spinner: 'earth' });
		this.#spinner.start('Firing up Reddit bot');

		// Snoowrap config
		this.#snoowrap = config.snoowrap;

		try {
			this.#r = new Snoowrap({
				username: this.#snoowrap.username,
				userAgent: this.#snoowrap.userAgent,
				clientId: this.#snoowrap.clientId,
				clientSecret: this.#snoowrap.clientSecret,
				password: this.#snoowrap.password
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
			this.#loki = config.loki;

			// LokiDb config
			this.#db = new Loki(this.#loki.db, {
				autoload: this.#loki.autoload,
				autosave: this.#loki.autosave,
				autosaveInterval: this.#loki.autosaveInterval,
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
					this.#spinner.start(`Checking for mentions and messages: ${Math.round(1_000_000 / this.#rate) / 1_000}Hz`);

					this.#updateInterval = setInterval(() => {
						this.#r.getInbox({ filter: 'unread' }).then((mentions) => {
							if (mentions.length > 0) {
								// Handle mentions
								for (let i = 0; i < mentions.length; i++) {
									const mention = mentions[i], tag = `u/${this.#snoowrap.username}`, regex = new RegExp(`u\/${this.#snoowrap.username}.*$`, `gm`);
									if (!mention.was_comment && mention.body.includes(tag)) continue;

									const finds = replies.find({ contentId: mention.id });
									if (!finds.length > 0) {
										// reply to mention and update databse
										const match = regex.exec(mention.body);
										this.reply(mention, match[0]);
										replies.insert({ contentId: mention.id });
										this.#db.save();
									}
								};

								this.#spinner.spinner = 'earth';
								this.#spinner.start(`Checking for mention: ${Math.round(1_000_000 / this.#rate) / 1_000}Hz`);
							};
						}).catch((error) => {
							clearInterval(this.#updateInterval);
							this.#spinner.fail(`[UPDATE_INTERVAL]: ${error}`);
						});

						// Clear inbox somehow
					}, this.#rate)
				}
			});
		} catch (error) {
			this.#spinner.fail(`[BOT_ERROR] ${error.message}`)
		}
	}
	reply(mention, querry) {
		this.#spinner.info(`[BOT] Replying to mention (${mention.id}), author (${mention.author.name})`)
	}
}