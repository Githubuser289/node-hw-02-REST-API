const Contact = require("../models/contacts");

const listContacts = async () => {
  try {
    return Contact.find();
  } catch (error) {
    console.error(error);
  }
};

const getContactById = async (contactId) => {
  try {
    return Contact.findById(contactId);
  } catch (error) {
    console.error(error);
  }
};

const removeContact = async (contactId) => {
  try {
    const deletedContact = await Contact.findByIdAndDelete(contactId);
    return deletedContact;
  } catch (error) {
    console.error(error);
    throw error;
  }
};

const addContact = async (contact) => {
  try {
    const newContact = await Contact.create(contact);
    return newContact;
  } catch (error) {
    throw error;
  }
};

const updateContact = async (contactId, body) => {
  try {
    const updatedContact = await Contact.findByIdAndUpdate(contactId, body, {
      new: true,
    });
    return updatedContact;
  } catch (error) {
    throw error;
  }
};

const updateStatusContact = async (contactId, body) => {
  try {
    const patchedContact = await Contact.findByIdAndUpdate(contactId, body, {
      new: true,
    });
    return patchedContact;
  } catch (error) {
    throw error;
  }
};

module.exports = {
  listContacts,
  getContactById,
  removeContact,
  addContact,
  updateContact,
  updateStatusContact,
};
